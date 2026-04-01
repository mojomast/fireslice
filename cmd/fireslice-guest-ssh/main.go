package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	gossh "golang.org/x/crypto/ssh"
)

const (
	listenAddr         = "0.0.0.0:22"
	authorizedKeysPath = "/home/ussycode/.ssh/authorized_keys"
	hostKeyPath        = "/etc/ssh/fireslice_host_ed25519_key"
	controlKeyPath     = "/etc/ssh/fireslice_control_authorized_key"
	defaultUser        = "ussycode"
)

func main() {
	signer, err := loadOrCreateHostKey(hostKeyPath)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	authorized, err := loadAuthorizedKeys(authorizedKeysPath, controlKeyPath)
	if err != nil {
		log.Fatalf("authorized keys: %v", err)
	}
	server := &gossh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if conn.User() != defaultUser {
				return nil, fmt.Errorf("unknown user")
			}
			if _, ok := authorized[string(key.Marshal())]; !ok {
				return nil, fmt.Errorf("unauthorized key")
			}
			return nil, nil
		},
	}
	server.AddHostKey(signer)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("fireslice guest ssh listening on %s", listenAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, server)
	}
}

func handleConn(conn net.Conn, cfg *gossh.ServerConfig) {
	defer conn.Close()
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		log.Printf("handshake: %v", err)
		return
	}
	defer sshConn.Close()
	go gossh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go serveSession(channel, requests)
	}
}

func serveSession(ch gossh.Channel, requests <-chan *gossh.Request) {
	defer ch.Close()
	cmdPath := "/bin/sh"
	cmdArgs := []string{"-l"}
	cmd := exec.Command(cmdPath, cmdArgs...)
	cmd.Dir = "/home/ussycode"
	cmd.Env = append(os.Environ(), "HOME=/home/ussycode", "USER=ussycode", "LOGNAME=ussycode", "SHELL=/bin/sh")

	started := false
	for req := range requests {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "shell":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			if err := runCommand(ch, cmd); err != nil {
				_, _ = io.WriteString(ch.Stderr(), err.Error()+"\n")
			}
			started = true
			return
		case "exec":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			payload := req.Payload
			if len(payload) < 4 {
				_ = req.Reply(false, nil)
				return
			}
			cmdline := string(payload[4:])
			cmd = exec.Command("/bin/sh", "-lc", cmdline)
			cmd.Dir = "/home/ussycode"
			cmd.Env = append(os.Environ(), "HOME=/home/ussycode", "USER=ussycode", "LOGNAME=ussycode", "SHELL=/bin/sh")
			_ = req.Reply(true, nil)
			if err := runCommand(ch, cmd); err != nil {
				_, _ = io.WriteString(ch.Stderr(), err.Error()+"\n")
			}
			started = true
			return
		case "env":
			_ = req.Reply(true, nil)
		case "window-change":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
	if !started {
		_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{Status: 1}))
	}
}

func runCommand(ch gossh.Channel, cmd *exec.Cmd) error {
	cmd.Stdin = ch
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	if err := dropToUssycode(cmd); err != nil {
		return fmt.Errorf("failed to prepare session: %w", err)
	}
	status := uint32(0)
	if err := cmd.Run(); err != nil {
		status = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			status = uint32(exitErr.ExitCode())
		} else {
			return err
		}
	}
	_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{Status: status}))
	return nil
}

func dropToUssycode(cmd *exec.Cmd) error {
	u, err := user.Lookup(defaultUser)
	if err != nil {
		return err
	}
	uid := atoiOrZero(u.Uid)
	gid := atoiOrZero(u.Gid)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	cmd.Env = append(cmd.Env, fmt.Sprintf("UID=%d", uid), fmt.Sprintf("GID=%d", gid))
	return nil
}

func loadAuthorizedKeys(paths ...string) (map[string]gossh.PublicKey, error) {
	out := make(map[string]gossh.PublicKey)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		s := bufio.NewScanner(bytes.NewReader(data))
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				continue
			}
			out[string(key.Marshal())] = key
		}
		if err := s.Err(); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no authorized keys found")
	}
	return out, nil
}

func loadOrCreateHostKey(path string) (gossh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		return gossh.ParsePrivateKey(data)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBlock, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		return nil, err
	}
	return gossh.NewSignerFromKey(priv)
}

func atoiOrZero(v string) int {
	var n int
	_, _ = fmt.Sscanf(v, "%d", &n)
	return n
}
