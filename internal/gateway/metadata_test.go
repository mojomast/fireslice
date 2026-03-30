package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/mojomast/fireslice/internal/db"
)

func TestMetadataSSHKeys_ResolvesCurrentOwnerKeysFromDB(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	owner, err := database.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatalf("CreateUser(owner): %v", err)
	}

	keyA := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice@laptop"
	keyB := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB alice@desktop"
	if _, err := database.AddSSHKey(ctx, owner.ID, keyA, "SHA256:alice-a", "laptop"); err != nil {
		t.Fatalf("AddSSHKey(keyA): %v", err)
	}
	if _, err := database.AddSSHKey(ctx, owner.ID, keyB, "SHA256:alice-b", "desktop"); err != nil {
		t.Fatalf("AddSSHKey(keyB): %v", err)
	}

	ip := "10.0.0.11"
	createRunningVM(t, ctx, database, owner.ID, "alice-box", ip)

	srv := NewServer(":0", logger)
	srv.SetDB(database)
	srv.RegisterVM(ip, &VMMetadata{
		UserID:  owner.ID,
		VMName:  "alice-box",
		SSHKeys: []string{"stale-key"},
	})

	body := fetchSSHKeys(t, srv, ip)
	got := sortedNonEmptyLines(body)
	want := sortedNonEmptyLines(keyA + "\n" + keyB + "\n")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected ssh keys\nwant: %q\ngot:  %q", want, got)
	}
}

func TestMetadataSSHKeys_NoKeysReturnsEmptySet(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	owner, err := database.CreateUser(ctx, "bob")
	if err != nil {
		t.Fatalf("CreateUser(owner): %v", err)
	}

	ip := "10.0.0.12"
	createRunningVM(t, ctx, database, owner.ID, "bob-box", ip)

	srv := NewServer(":0", logger)
	srv.SetDB(database)
	srv.RegisterVM(ip, &VMMetadata{
		UserID:  owner.ID,
		VMName:  "bob-box",
		SSHKeys: []string{"stale-key-that-must-be-ignored"},
	})

	body := fetchSSHKeys(t, srv, ip)
	if body != "" {
		t.Fatalf("expected empty ssh key set, got %q", body)
	}
}

func TestMetadataSSHKeys_UsesVMOwnerWhenMetadataOwnerMismatches(t *testing.T) {
	database := testDB(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	owner, err := database.CreateUser(ctx, "carol")
	if err != nil {
		t.Fatalf("CreateUser(owner): %v", err)
	}
	wrongUser, err := database.CreateUser(ctx, "mallory")
	if err != nil {
		t.Fatalf("CreateUser(wrongUser): %v", err)
	}

	ownerKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC carol@host"
	wrongKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD mallory@host"
	if _, err := database.AddSSHKey(ctx, owner.ID, ownerKey, "SHA256:carol", "owner"); err != nil {
		t.Fatalf("AddSSHKey(owner): %v", err)
	}
	if _, err := database.AddSSHKey(ctx, wrongUser.ID, wrongKey, "SHA256:mallory", "wrong"); err != nil {
		t.Fatalf("AddSSHKey(wrong): %v", err)
	}

	ip := "10.0.0.13"
	createRunningVM(t, ctx, database, owner.ID, "carol-box", ip)

	srv := NewServer(":0", logger)
	srv.SetDB(database)
	srv.RegisterVM(ip, &VMMetadata{
		UserID:     wrongUser.ID,
		UserHandle: wrongUser.Handle,
		VMName:     "carol-box",
		SSHKeys:    []string{wrongKey},
	})

	body := fetchSSHKeys(t, srv, ip)
	got := sortedNonEmptyLines(body)
	want := []string{ownerKey}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("expected VM owner's keys from db, got %q", got)
	}
}

func createRunningVM(t *testing.T, ctx context.Context, database *db.DB, userID int64, name, ip string) {
	t.Helper()

	vm, err := database.CreateVM(ctx, userID, name, "ussyuntu", 1, 512, 5)
	if err != nil {
		t.Fatalf("CreateVM(%s): %v", name, err)
	}
	if err := database.UpdateVMStatus(ctx, vm.ID, "running", nil, &ip, nil, nil); err != nil {
		t.Fatalf("UpdateVMStatus(%s): %v", name, err)
	}
}

func fetchSSHKeys(t *testing.T, srv *Server, ip string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/ssh-keys", nil)
	req.RemoteAddr = ip + ":12345"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(body)
}

func sortedNonEmptyLines(s string) []string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	sort.Strings(lines)
	return lines
}
