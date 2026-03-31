package vm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// mockExecutor records commands and returns pre-configured responses.
type mockExecutor struct {
	commands  []string
	responses map[string]mockExecResponse
}

type mockExecResponse struct {
	output []byte
	err    error
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		responses: make(map[string]mockExecResponse),
	}
}

func (m *mockExecutor) SetResponse(key string, output []byte, err error) {
	m.responses[key] = mockExecResponse{output: output, err: err}
}

func (m *mockExecutor) Execute(_ context.Context, name string, args ...string) ([]byte, error) {
	full := name + " " + strings.Join(args, " ")
	m.commands = append(m.commands, full)

	if resp, ok := m.responses[full]; ok {
		return resp.output, resp.err
	}
	return nil, nil
}

func (m *mockExecutor) CommandCount() int {
	return len(m.commands)
}

func (m *mockExecutor) LastCommand() string {
	if len(m.commands) == 0 {
		return ""
	}
	return m.commands[len(m.commands)-1]
}

func (m *mockExecutor) HasCommand(substr string) bool {
	for _, cmd := range m.commands {
		if strings.Contains(cmd, substr) {
			return true
		}
	}
	return false
}

func testNftLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNftablesSetupNAT_Success(t *testing.T) {
	exec := newMockExecutor()
	nft := NewNftablesManager(exec, testNftLogger())

	err := nft.SetupNAT(context.Background(), "ussy0", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("SetupNAT() error = %v", err)
	}

	if exec.CommandCount() == 0 {
		t.Fatal("expected nft commands to run")
	}
	if !exec.HasCommand("nft add table inet ussycode") {
		t.Error("expected 'nft add table' command")
	}
	if !exec.HasCommand("base-metadata-redirect") {
		t.Error("expected metadata redirect base rule")
	}
}

func TestNftablesSetupNAT_Idempotent(t *testing.T) {
	exec := newMockExecutor()
	nft := NewNftablesManager(exec, testNftLogger())
	listWithBaseRules := `table inet ussycode {
    chain prerouting {
        iifname "ussy0" ip daddr 169.254.169.254 tcp dport 80 redirect to :8083 comment "base-metadata-redirect" # handle 1
    }
    chain postrouting {
        oifname != "ussy0" ip saddr 10.0.0.0/24 masquerade comment "base-masquerade" # handle 2
    }
    chain forward {
        iifname "ussy0" accept comment "base-forward-from-bridge" # handle 3
        oifname "ussy0" ct state established,related accept comment "base-forward-to-bridge" # handle 4
    }
}`
	exec.SetResponse("nft --handle list chain inet ussycode prerouting", []byte(listWithBaseRules), nil)
	exec.SetResponse("nft --handle list chain inet ussycode postrouting", []byte(listWithBaseRules), nil)
	exec.SetResponse("nft --handle list chain inet ussycode forward", []byte(listWithBaseRules), nil)

	_ = nft.SetupNAT(context.Background(), "ussy0", "10.0.0.0/24")

	baseAdds := 0
	for _, cmd := range exec.commands {
		if strings.Contains(cmd, "base-") && strings.Contains(cmd, "add rule") {
			baseAdds++
		}
	}
	if baseAdds != 0 {
		t.Fatalf("expected no duplicate base rule insertion, got %d commands: %v", baseAdds, exec.commands)
	}
}

func TestNftablesCleanupNAT_Success(t *testing.T) {
	exec := newMockExecutor()
	nft := NewNftablesManager(exec, testNftLogger())

	exec.SetResponse("nft delete table inet ussycode", nil, nil)

	err := nft.CleanupNAT(context.Background(), "ussy0", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("CleanupNAT() error = %v", err)
	}
}

func TestNftablesCleanupNAT_AlreadyGone(t *testing.T) {
	exec := newMockExecutor()
	nft := NewNftablesManager(exec, testNftLogger())

	exec.SetResponse("nft delete table inet ussycode",
		[]byte("Error: No such file or directory"),
		fmt.Errorf("exit status 1"))

	err := nft.CleanupNAT(context.Background(), "ussy0", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("CleanupNAT() should be idempotent, got error = %v", err)
	}
}

func TestNftablesAddVMRules_Success(t *testing.T) {
	exec := newMockExecutor()
	nft := NewNftablesManager(exec, testNftLogger())

	err := nft.AddVMRules(context.Background(), "42", "tap-42", "10.0.0.2", "ussy0")
	if err != nil {
		t.Fatalf("AddVMRules() error = %v", err)
	}

	// Should have 2 commands: forward rule + return rule
	if exec.CommandCount() != 2 {
		t.Errorf("expected 2 commands, got %d", exec.CommandCount())
	}

	// Check that both rules reference the VM
	forwardFound := false
	returnFound := false
	for _, cmd := range exec.commands {
		if strings.Contains(cmd, "tap-42") && strings.Contains(cmd, "saddr") {
			forwardFound = true
		}
		if strings.Contains(cmd, "tap-42") && strings.Contains(cmd, "daddr") {
			returnFound = true
		}
	}
	if !forwardFound {
		t.Error("expected forward rule with tap-42 and saddr")
	}
	if !returnFound {
		t.Error("expected return rule with tap-42 and daddr")
	}
}

func TestNftablesRemoveVMRules_Success(t *testing.T) {
	exec := newMockExecutor()
	nft := NewNftablesManager(exec, testNftLogger())

	// Mock: listing forward chain returns rules with handles
	listOutput := `table inet ussycode {
    chain forward {
        type filter hook forward priority 0; policy drop;
        iifname "ussy0" accept # handle 1
        oifname "ussy0" ct state established,related accept # handle 2
        iifname "tap-42" ip saddr 10.0.0.2 accept comment "vm-42" # handle 5
        oifname "tap-42" ip daddr 10.0.0.2 accept comment "vm-42-return" # handle 6
    }
}`

	exec.SetResponse("nft --handle list chain inet ussycode forward",
		[]byte(listOutput), nil)

	err := nft.RemoveVMRules(context.Background(), "42", "tap-42", "ussy0")
	if err != nil {
		t.Fatalf("RemoveVMRules() error = %v", err)
	}

	// Should have 3 commands: list + 2 deletes (handles 5 and 6)
	if exec.CommandCount() != 3 {
		t.Errorf("expected 3 commands (list + 2 deletes), got %d: %v", exec.CommandCount(), exec.commands)
	}

	// Verify delete commands reference the correct handles
	if !exec.HasCommand("handle 5") {
		t.Error("expected delete for handle 5")
	}
	if !exec.HasCommand("handle 6") {
		t.Error("expected delete for handle 6")
	}
}

func TestNftablesRemoveVMRules_NoTable(t *testing.T) {
	exec := newMockExecutor()
	nft := NewNftablesManager(exec, testNftLogger())

	exec.SetResponse("nft --handle list chain inet ussycode forward",
		[]byte("Error: No such file or directory"),
		fmt.Errorf("exit status 1"))

	err := nft.RemoveVMRules(context.Background(), "42", "tap-42", "ussy0")
	if err != nil {
		t.Fatalf("RemoveVMRules() should be idempotent when table doesn't exist, got error = %v", err)
	}
}

func TestParseNftHandles(t *testing.T) {
	output := `table inet ussycode {
    chain forward {
        type filter hook forward priority 0; policy drop;
        iifname "ussy0" accept # handle 1
        oifname "ussy0" ct state established,related accept # handle 2
        iifname "tap-42" ip saddr 10.0.0.2 accept comment "vm-42" # handle 5
        oifname "tap-42" ip daddr 10.0.0.2 accept comment "vm-42-return" # handle 6
        iifname "tap-99" ip saddr 10.0.0.3 accept comment "vm-99" # handle 7
    }
}`

	handles := parseNftHandles(output, "vm-42")
	if len(handles) != 2 {
		t.Fatalf("expected 2 handles, got %d: %v", len(handles), handles)
	}
	if handles[0] != "5" {
		t.Errorf("handles[0] = %q, want %q", handles[0], "5")
	}
	if handles[1] != "6" {
		t.Errorf("handles[1] = %q, want %q", handles[1], "6")
	}
}

func TestParseNftHandles_NoMatch(t *testing.T) {
	output := `table inet ussycode {
    chain forward {
        type filter hook forward priority 0; policy drop;
        iifname "ussy0" accept # handle 1
    }
}`
	handles := parseNftHandles(output, "vm-42")
	if len(handles) != 0 {
		t.Errorf("expected 0 handles for non-matching comment, got %d", len(handles))
	}
}

func TestFirewallManagerInterface(t *testing.T) {
	var _ FirewallManager = (*NftablesManager)(nil)
}
