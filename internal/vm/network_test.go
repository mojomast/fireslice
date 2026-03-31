package vm

import (
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
)

func TestNetworkManagerLoadLeasesSkipsReusedIPs(t *testing.T) {
	t.Parallel()

	nm, err := NewNetworkManager("ussy0", "10.0.0.0/24", slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("NewNetworkManager() error = %v", err)
	}
	if err := nm.LoadLeases(map[string]string{
		"3": "10.0.0.2",
		"4": "10.0.0.3",
	}); err != nil {
		t.Fatalf("LoadLeases() error = %v", err)
	}

	if nm.nextIP == 0 {
		t.Fatal("LoadLeases() left nextIP unset")
	}
	highestLease := binary.BigEndian.Uint32(net.ParseIP("10.0.0.3").To4())
	if nm.nextIP <= highestLease {
		t.Fatalf("LoadLeases() nextIP = %d, want value after highest lease", nm.nextIP)
	}
}

func TestNetworkManagerAllocateReleaseUsesGuestHostRoutes(t *testing.T) {
	t.Parallel()

	var cmds []string
	originalRunCmd := runCmd
	runCmd = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil
	}
	defer func() { runCmd = originalRunCmd }()

	nm, err := NewNetworkManager("ussy0", "10.0.0.0/24", slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("NewNetworkManager() error = %v", err)
	}

	cfg, err := nm.AllocateNetwork("42")
	if err != nil {
		t.Fatalf("AllocateNetwork() error = %v", err)
	}

	wantAdd := "ip route replace " + cfg.GuestIP + "/32 dev " + cfg.TapDevice
	if !containsCommand(cmds, wantAdd) {
		t.Fatalf("AllocateNetwork() commands = %v, want %q", cmds, wantAdd)
	}

	cmds = nil
	if err := nm.ReleaseNetwork("42", cfg.TapDevice); err != nil {
		t.Fatalf("ReleaseNetwork() error = %v", err)
	}

	wantDel := "ip route del " + cfg.GuestIP + "/32 dev " + cfg.TapDevice
	if !containsCommand(cmds, wantDel) {
		t.Fatalf("ReleaseNetwork() commands = %v, want %q", cmds, wantDel)
	}
	if !containsCommand(cmds, "ip link del "+cfg.TapDevice) {
		t.Fatalf("ReleaseNetwork() commands = %v, want tap deletion", cmds)
	}
}

func containsCommand(cmds []string, want string) bool {
	for _, cmd := range cmds {
		if cmd == want {
			return true
		}
	}
	return false
}
