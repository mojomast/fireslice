package sshgate

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/mojomast/fireslice/internal/db"
)

func TestControlResolveRequiresOwnershipAndReachableVM(t *testing.T) {
	ctx := context.Background()
	database := openTestDB(t)

	owner, err := database.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatalf("CreateUser(owner): %v", err)
	}
	other, err := database.CreateUser(ctx, "bob")
	if err != nil {
		t.Fatalf("CreateUser(other): %v", err)
	}
	if _, err := database.AddSSHKey(ctx, owner.ID, "ssh-ed25519 AAAA alice@test", "SHA256:owner", "owner"); err != nil {
		t.Fatalf("AddSSHKey(owner): %v", err)
	}
	if _, err := database.AddSSHKey(ctx, other.ID, "ssh-ed25519 AAAA bob@test", "SHA256:other", "other"); err != nil {
		t.Fatalf("AddSSHKey(other): %v", err)
	}
	vmRecord, err := database.CreateVM(ctx, owner.ID, "slice-1", "ubuntu:24.04", 1, 512, 5)
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	ip := "10.77.0.5"
	if err := database.UpdateVMStatus(ctx, vmRecord.ID, "running", nil, &ip, nil, nil); err != nil {
		t.Fatalf("UpdateVMStatus(running): %v", err)
	}

	server := &ControlServer{DB: database}

	t.Run("owner can resolve running vm", func(t *testing.T) {
		resp, err := server.resolve(ctx, ResolveRequest{Fingerprint: "SHA256:owner", VMName: "slice-1"})
		if err != nil {
			t.Fatalf("resolve(): %v", err)
		}
		if resp.UserHandle != "alice" {
			t.Fatalf("UserHandle = %q, want alice", resp.UserHandle)
		}
		if resp.GuestIP != ip {
			t.Fatalf("GuestIP = %q, want %q", resp.GuestIP, ip)
		}
		if resp.SSHUser != "ussycode" {
			t.Fatalf("SSHUser = %q, want ussycode", resp.SSHUser)
		}
	})

	t.Run("other user cannot resolve foreign vm", func(t *testing.T) {
		_, err := server.resolve(ctx, ResolveRequest{Fingerprint: "SHA256:other", VMName: "slice-1"})
		if err == nil || err.Error() != "vm not found" {
			t.Fatalf("resolve() error = %v, want vm not found", err)
		}
	})

	t.Run("vm must be running with ip", func(t *testing.T) {
		if err := database.UpdateVMStatus(ctx, vmRecord.ID, "stopped", nil, nil, nil, nil); err != nil {
			t.Fatalf("UpdateVMStatus(stopped): %v", err)
		}
		_, err := server.resolve(ctx, ResolveRequest{Fingerprint: "SHA256:owner", VMName: "slice-1"})
		if err == nil || err.Error() != "vm is not currently reachable" {
			t.Fatalf("resolve() error = %v, want vm is not currently reachable", err)
		}
	})
}

func TestRelayHandleConnRejectsInvalidRequests(t *testing.T) {
	server := &RelayServer{Subnet: "10.77.0.0/24"}

	t.Run("only port 22 is allowed", func(t *testing.T) {
		client, relay := net.Pipe()
		defer client.Close()
		defer relay.Close()
		go server.handleConn(relay)
		_, _ = client.Write([]byte(`{"guest_ip":"10.77.0.5","port":2222}` + "\n"))
		buf := make([]byte, 128)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if got := string(buf[:n]); got != "ERR only port 22 is allowed\n" {
			t.Fatalf("response = %q, want port rejection", got)
		}
	})

	t.Run("guest ip must stay inside subnet", func(t *testing.T) {
		client, relay := net.Pipe()
		defer client.Close()
		defer relay.Close()
		go server.handleConn(relay)
		_, _ = client.Write([]byte(`{"guest_ip":"192.168.1.9","port":22}` + "\n"))
		buf := make([]byte, 128)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if got := string(buf[:n]); got != "ERR guest ip outside allowed subnet\n" {
			t.Fatalf("response = %q, want subnet rejection", got)
		}
	})
}

func TestIsAllowedIP(t *testing.T) {
	if !isAllowedIP("10.77.0.0/24", "10.77.0.5") {
		t.Fatal("expected ip inside subnet to be allowed")
	}
	if isAllowedIP("10.77.0.0/24", "10.88.0.5") {
		t.Fatal("expected ip outside subnet to be rejected")
	}
	if isAllowedIP("bad-cidr", "10.77.0.5") {
		t.Fatal("expected invalid subnet to be rejected")
	}
	if isAllowedIP("10.77.0.0/24", "not-an-ip") {
		t.Fatal("expected invalid ip to be rejected")
	}
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshgate.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return database
}
