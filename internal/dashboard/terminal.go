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
	"time"

	"github.com/mojomast/fireslice/internal/sshgate"
	gossh "golang.org/x/crypto/ssh"
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
			"id":   vmRecord.ID,
			"name": vmRecord.Name,
		},
		"Principal": principal,
		"IsAdmin":   principal.Role == "admin",
	})
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
	relaySock := h.config["ssh_relay_sock"]
	guestKeyPath := h.config["guest_ssh_key_path"]
	if relaySock == "" || guestKeyPath == "" {
		return "", fmt.Errorf("terminal ssh plumbing is not configured")
	}
	relayConn, err := net.Dial("unix", relaySock)
	if err != nil {
		return "", err
	}
	defer relayConn.Close()
	if err := json.NewEncoder(relayConn).Encode(&sshgate.RelayRequest{GuestIP: guestIP, Port: 22}); err != nil {
		return "", err
	}
	reader := bufio.NewReader(relayConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(line, "OK") {
		return "", errors.New(strings.TrimSpace(line))
	}
	signer, err := sshgate.LoadSigner(guestKeyPath)
	if err != nil {
		return "", err
	}
	clientConn, chans, reqs, err := gossh.NewClientConn(&bufferedConn{Conn: relayConn, reader: reader}, guestIP+":22", &gossh.ClientConfig{
		User:            "ussycode",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return "", err
	}
	client := gossh.NewClient(clientConn, chans, reqs)
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
