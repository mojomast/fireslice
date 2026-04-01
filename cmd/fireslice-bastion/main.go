package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mojomast/fireslice/internal/fireslice"
	"github.com/mojomast/fireslice/internal/sshbastion"
	"github.com/mojomast/fireslice/internal/sshgate"
)

func main() {
	cfg := fireslice.DefaultConfig()
	cfg.RegisterFlags(flag.CommandLine)
	flag.Parse()

	level := slog.LevelInfo
	if cfg.Debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if _, err := sshgate.EnsureKeypair(cfg.SSHHostKeyPath); err != nil {
		log.Fatalf("ensure bastion host key: %v", err)
	}
	bastion := &sshbastion.Server{
		SSHAddr:      cfg.BastionSSHAddr,
		HTTPAddr:     cfg.BastionHTTPAddr,
		Domain:       cfg.Domain,
		HostKeyPath:  cfg.SSHHostKeyPath,
		GuestKeyPath: cfg.GuestSSHKeyPath,
		ControlSock:  cfg.SSHControlSock,
		RelaySock:    cfg.SSHRelaySock,
		Logger:       logger.With("component", "ssh-bastion"),
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := bastion.Start(ctx); err != nil {
		log.Fatalf("start bastion: %v", err)
	}
}
