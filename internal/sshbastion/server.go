package sshbastion

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/creack/pty/v2"
	gssh "github.com/gliderlabs/ssh"
	"github.com/mojomast/fireslice/internal/sshgate"
	gossh "golang.org/x/crypto/ssh"
)

type Server struct {
	SSHAddr      string
	HTTPAddr     string
	Domain       string
	HostKeyPath  string
	GuestKeyPath string
	ControlSock  string
	RelaySock    string
	Logger       *slog.Logger

	server *gssh.Server
	http   *http.Server
}

func (s *Server) Start(ctx context.Context) error {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	signer, err := sshgate.LoadSigner(s.HostKeyPath)
	if err != nil {
		return err
	}
	s.server = &gssh.Server{
		Addr:             s.SSHAddr,
		Handler:          s.handleSession,
		PublicKeyHandler: s.publicKeyHandler,
		HostSigners:      []gssh.Signer{signer},
		IdleTimeout:      10 * time.Minute,
		MaxTimeout:       12 * time.Hour,
	}
	s.http = &http.Server{Addr: s.HTTPAddr, Handler: http.HandlerFunc(s.handleHealth)}
	go func() {
		<-ctx.Done()
		_ = s.server.Shutdown(context.Background())
		_ = s.http.Shutdown(context.Background())
	}()
	go func() {
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.Logger.Error("bastion http server exited", "error", err)
		}
	}()
	s.Logger.Info("ssh bastion listening", "addr", s.SSHAddr)
	return s.server.ListenAndServe()
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func (s *Server) publicKeyHandler(ctx gssh.Context, key gssh.PublicKey) bool {
	ctx.SetValue("fingerprint", gossh.FingerprintSHA256(key))
	return true
}

func (s *Server) handleSession(session gssh.Session) {
	defer closeSession(session)
	fingerprint, _ := session.Context().Value("fingerprint").(string)
	vmName := strings.TrimSpace(session.User())
	if vmName == "" {
		io.WriteString(session, "specify the slice name as the SSH user, e.g. ssh my-slice@host\n")
		session.Exit(1)
		return
	}
	resolved, err := s.resolveVM(fingerprint, vmName)
	if err != nil {
		io.WriteString(session, err.Error()+"\n")
		session.Exit(1)
		return
	}
	if err := s.bridgeToGuest(session, resolved); err != nil {
		io.WriteString(session, err.Error()+"\n")
		session.Exit(1)
		return
	}
	session.Exit(0)
}

func closeSession(session gssh.Session) {
	if closer, ok := any(session).(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func (s *Server) resolveVM(fingerprint, vmName string) (*sshgate.ResolveResponse, error) {
	conn, err := net.Dial("unix", s.ControlSock)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(&sshgate.ResolveRequest{Fingerprint: fingerprint, VMName: vmName}); err != nil {
		return nil, err
	}
	var resp sshgate.ResolveResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.VMID == 0 {
		if resp.Error != "" {
			return nil, errors.New(resp.Error)
		}
		return nil, fmt.Errorf("vm lookup failed")
	}
	return &resp, nil
}

func (s *Server) bridgeToGuest(session gssh.Session, resolved *sshgate.ResolveResponse) error {
	relayConn, err := net.Dial("unix", s.RelaySock)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(relayConn).Encode(&sshgate.RelayRequest{GuestIP: resolved.GuestIP, Port: 22}); err != nil {
		relayConn.Close()
		return err
	}
	reader := bufio.NewReader(relayConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		relayConn.Close()
		return err
	}
	if !strings.HasPrefix(line, "OK") {
		relayConn.Close()
		return errors.New(strings.TrimSpace(line))
	}
	clientKey, err := sshgate.LoadSigner(s.GuestKeyPath)
	if err != nil {
		relayConn.Close()
		return err
	}
	clientConn, chans, reqs, err := gossh.NewClientConn(&bufferedConn{Conn: relayConn, reader: reader}, resolved.GuestIP+":22", &gossh.ClientConfig{
		User:            resolved.SSHUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientKey)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		relayConn.Close()
		return err
	}
	client := gossh.NewClient(clientConn, chans, reqs)
	defer client.Close()
	guestSession, err := client.NewSession()
	if err != nil {
		return err
	}
	defer guestSession.Close()
	ptyReq, winCh, isPty := session.Pty()
	ws := &pty.Winsize{Rows: 24, Cols: 80}
	if isPty {
		ws.Rows = uint16(ptyReq.Window.Height)
		ws.Cols = uint16(ptyReq.Window.Width)
		if err := guestSession.RequestPty(ptyReq.Term, int(ws.Rows), int(ws.Cols), gossh.TerminalModes{}); err != nil {
			return err
		}
	}
	guestSession.Stdout = session
	guestSession.Stderr = session.Stderr()
	stdin, err := guestSession.StdinPipe()
	if err != nil {
		return err
	}
	go io.Copy(stdin, session)
	if isPty {
		go func() {
			for win := range winCh {
				_ = guestSession.WindowChange(win.Height, win.Width)
			}
		}()
	}
	if strings.TrimSpace(session.RawCommand()) != "" {
		return guestSession.Run(session.RawCommand())
	}
	if err := guestSession.Shell(); err != nil {
		return err
	}
	return guestSession.Wait()
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
