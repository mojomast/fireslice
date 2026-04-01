package sshgate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
)

type RelayServer struct {
	Sock   string
	Subnet string
	Logger *slog.Logger
}

type RelayRequest struct {
	GuestIP string `json:"guest_ip"`
	Port    int    `json:"port"`
}

func (s *RelayServer) Serve(ctx context.Context) error {
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

func (s *RelayServer) handleConn(conn net.Conn) {
	defer conn.Close()
	var req RelayRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_, _ = conn.Write([]byte("ERR invalid request\n"))
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.Port != 22 {
		_, _ = conn.Write([]byte("ERR only port 22 is allowed\n"))
		return
	}
	guestIP := strings.TrimSpace(req.GuestIP)
	if !isAllowedIP(s.Subnet, guestIP) {
		_, _ = conn.Write([]byte("ERR guest ip outside allowed subnet\n"))
		return
	}
	upstream, err := net.Dial("tcp", fmt.Sprintf("%s:%d", guestIP, req.Port))
	if err != nil {
		_, _ = conn.Write([]byte("ERR connect failed\n"))
		return
	}
	defer upstream.Close()
	_, _ = conn.Write([]byte("OK\n"))
	go io.Copy(upstream, conn)
	_, _ = io.Copy(conn, upstream)
}

func isAllowedIP(subnet, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	_, cidr, err := net.ParseCIDR(subnet)
	if err != nil {
		return false
	}
	return cidr.Contains(parsed)
}
