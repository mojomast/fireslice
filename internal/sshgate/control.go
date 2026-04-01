package sshgate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/mojomast/fireslice/internal/db"
	gossh "golang.org/x/crypto/ssh"
)

type ControlServer struct {
	DB     *db.DB
	Logger *slog.Logger
	Sock   string
}

type ResolveRequest struct {
	Fingerprint string `json:"fingerprint"`
	VMName      string `json:"vm_name"`
}

type ResolveResponse struct {
	Error      string `json:"error,omitempty"`
	UserHandle string `json:"user_handle"`
	VMID       int64  `json:"vm_id"`
	VMName     string `json:"vm_name"`
	GuestIP    string `json:"guest_ip"`
	Status     string `json:"status"`
	SSHUser    string `json:"ssh_user"`
}

func (s *ControlServer) Serve(ctx context.Context) error {
	if s.DB == nil {
		return fmt.Errorf("control db is required")
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if err := os.RemoveAll(s.Sock); err != nil {
		return err
	}
	ln, err := net.Listen("unix", s.Sock)
	if err != nil {
		return err
	}
	_ = os.Chmod(s.Sock, 0666)
	defer os.Remove(s.Sock)
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *ControlServer) handleConn(conn net.Conn) {
	defer conn.Close()
	var req ResolveRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(map[string]string{"error": err.Error()})
		return
	}
	resp, err := s.resolve(context.Background(), req)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(&ResolveResponse{Error: err.Error()})
		return
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *ControlServer) resolve(ctx context.Context, req ResolveRequest) (*ResolveResponse, error) {
	if strings.TrimSpace(req.Fingerprint) == "" || strings.TrimSpace(req.VMName) == "" {
		return nil, fmt.Errorf("fingerprint and vm_name are required")
	}
	user, err := s.DB.UserByFingerprint(ctx, strings.TrimSpace(req.Fingerprint))
	if err != nil {
		return nil, err
	}
	vmRecord, err := s.DB.VMByUserAndName(ctx, user.ID, strings.TrimSpace(req.VMName))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("vm not found")
		}
		return nil, err
	}
	if vmRecord.Status != "running" || !vmRecord.IPAddress.Valid {
		return nil, fmt.Errorf("vm is not currently reachable")
	}
	return &ResolveResponse{
		UserHandle: user.Handle,
		VMID:       vmRecord.ID,
		VMName:     vmRecord.Name,
		GuestIP:    vmRecord.IPAddress.String,
		Status:     vmRecord.Status,
		SSHUser:    "ussycode",
	}, nil
}

func FingerprintAuthorizedKey(publicKey []byte) (string, error) {
	key, _, _, _, err := gossh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return "", err
	}
	return gossh.FingerprintSHA256(key), nil
}
