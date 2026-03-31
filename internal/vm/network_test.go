package vm

import (
	"encoding/binary"
	"log/slog"
	"net"
	"os"
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
