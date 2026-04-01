package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mojomast/fireslice/internal/sshgate"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

func (h *Handler) renderTerminal(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal) {
	id := vmIDFromPath(r.URL.Path, "/terminal")
	if id == 0 || !h.canManageVM(r.Context(), id, principal) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	vmRecord, err := h.service.VMs.GetVM(r.Context(), id)
	if err != nil {
		h.renderError(w, err.Error())
		return
	}
	_ = h.templates.ExecuteTemplate(w, "vm_terminal.html", map[string]any{
		"VM": map[string]any{
			"id":      vmRecord.ID,
			"name":    vmRecord.Name,
			"ws_path": fmt.Sprintf("/vms/%d/terminal/ws", vmRecord.ID),
		},
		"Principal": principal,
		"IsAdmin":   principal.Role == "admin",
	})
}

func (h *Handler) handleTerminalWebSocket(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal) {
	id := vmIDFromPath(r.URL.Path, "/terminal/ws")
	if id == 0 || !h.canManageVM(r.Context(), id, principal) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	vmRecord, err := h.service.VMs.GetVM(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if vmRecord.Status != "running" || !vmRecord.IPAddress.Valid {
		http.Error(w, "vm is not running", http.StatusConflict)
		return
	}
	websocket.Handler(func(ws *websocket.Conn) {
		h.serveTerminalWebSocket(ws, vmRecord.IPAddress.String)
	}).ServeHTTP(w, r)
}

func (h *Handler) handleTerminalStream(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal) {
	id := vmIDFromPath(r.URL.Path, "/terminal/stream")
	if id == 0 || !h.canManageVM(r.Context(), id, principal) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	vmRecord, err := h.service.VMs.GetVM(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if vmRecord.Status != "running" || !vmRecord.IPAddress.Valid {
		http.Error(w, "vm is not running", http.StatusConflict)
		return
	}
	stdin := r.FormValue("input")
	output, err := h.runTerminalCommand(r.Context(), vmRecord.IPAddress.String, stdin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": output})
}

func (h *Handler) runTerminalCommand(ctx context.Context, guestIP, input string) (string, error) {
	client, err := h.newGuestSSHClient(ctx, guestIP)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var out strings.Builder
	session.Stdout = &out
	session.Stderr = &out
	cmd := "/bin/sh -lc " + shellEscape(input)
	if err := session.Run(cmd); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

func (h *Handler) serveTerminalWebSocket(ws *websocket.Conn, guestIP string) {
	defer ws.Close()
	client, err := h.newGuestSSHClient(context.Background(), guestIP)
	if err != nil {
		_ = sendTerminalMessage(ws, terminalMessage{Type: "error", Data: err.Error()})
		return
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		_ = sendTerminalMessage(ws, terminalMessage{Type: "error", Data: err.Error()})
		return
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = sendTerminalMessage(ws, terminalMessage{Type: "error", Data: err.Error()})
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = sendTerminalMessage(ws, terminalMessage{Type: "error", Data: err.Error()})
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = sendTerminalMessage(ws, terminalMessage{Type: "error", Data: err.Error()})
		return
	}
	if err := session.RequestPty("dumb", 24, 80, gossh.TerminalModes{}); err != nil {
		_ = sendTerminalMessage(ws, terminalMessage{Type: "error", Data: err.Error()})
		return
	}
	if err := session.Shell(); err != nil {
		_ = sendTerminalMessage(ws, terminalMessage{Type: "error", Data: err.Error()})
		return
	}
	sender := &terminalSender{ws: ws}
	go streamTerminalOutput(sender, stdout)
	go streamTerminalOutput(sender, stderr)
	waitErr := make(chan error, 1)
	go func() {
		waitErr <- session.Wait()
	}()
	recvErr := make(chan error, 1)
	go func() {
		for {
			var msg terminalMessage
			if err := websocket.JSON.Receive(ws, &msg); err != nil {
				recvErr <- err
				return
			}
			switch msg.Type {
			case "input":
				if _, err := io.WriteString(stdin, msg.Data); err != nil {
					recvErr <- err
					return
				}
			case "resize":
				if msg.Rows > 0 && msg.Cols > 0 {
					_ = session.WindowChange(msg.Rows, msg.Cols)
				}
			}
		}
	}()
	select {
	case err := <-waitErr:
		if err != nil && !errors.Is(err, io.EOF) {
			_ = sender.Send(terminalMessage{Type: "error", Data: err.Error()})
		}
		_ = sender.Send(terminalMessage{Type: "exit"})
	case <-recvErr:
	}
}

func (h *Handler) newGuestSSHClient(_ context.Context, guestIP string) (*gossh.Client, error) {
	relaySock := h.config["ssh_relay_sock"]
	guestKeyPath := h.config["guest_ssh_key_path"]
	if relaySock == "" || guestKeyPath == "" {
		return nil, fmt.Errorf("terminal ssh plumbing is not configured")
	}
	relayConn, err := net.Dial("unix", relaySock)
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(relayConn).Encode(&sshgate.RelayRequest{GuestIP: guestIP, Port: 22}); err != nil {
		relayConn.Close()
		return nil, err
	}
	reader := bufio.NewReader(relayConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		relayConn.Close()
		return nil, err
	}
	if !strings.HasPrefix(line, "OK") {
		relayConn.Close()
		return nil, errors.New(strings.TrimSpace(line))
	}
	signer, err := sshgate.LoadSigner(guestKeyPath)
	if err != nil {
		relayConn.Close()
		return nil, err
	}
	clientConn, chans, reqs, err := gossh.NewClientConn(&bufferedConn{Conn: relayConn, reader: reader}, guestIP+":22", &gossh.ClientConfig{
		User:            "ussycode",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		relayConn.Close()
		return nil, err
	}
	return gossh.NewClient(clientConn, chans, reqs), nil
}

type terminalMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Rows int    `json:"rows,omitempty"`
	Cols int    `json:"cols,omitempty"`
}

type terminalSender struct {
	mu sync.Mutex
	ws *websocket.Conn
}

func (s *terminalSender) Send(msg terminalMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return websocket.JSON.Send(s.ws, msg)
}

func sendTerminalMessage(ws *websocket.Conn, msg terminalMessage) error {
	return websocket.JSON.Send(ws, msg)
}

func streamTerminalOutput(sender *terminalSender, r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if sendErr := sender.Send(terminalMessage{Type: "output", Data: string(buf[:n])}); sendErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

var _ io.Reader = (*bufferedConn)(nil)
