package dashboard

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/fireslice"
	"github.com/mojomast/fireslice/internal/sessionauth"
	"golang.org/x/crypto/bcrypt"
)

func TestHandleTerminalStreamRequiresRunningVM(t *testing.T) {
	h := newTerminalTestHandler(t, map[int64]*db.VM{11: {
		ID:        11,
		UserID:    7,
		Name:      "hello1",
		Status:    "stopped",
		Image:     "ubuntu:24.04",
		IPAddress: sql.NullString{String: "10.0.0.2", Valid: true},
		CreatedAt: db.SQLiteTime{Time: time.Now()},
		UpdatedAt: db.SQLiteTime{Time: time.Now()},
	}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/vms/11/terminal/stream", strings.NewReader("input=pwd"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.handleTerminalStream(rec, req, dashboardPrincipal{UserID: 7, Username: "bob", Role: "user"})

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	if body := rec.Body.String(); !strings.Contains(body, "vm is not running") {
		t.Fatalf("body = %q, want vm is not running", body)
	}
}

func TestHandleTerminalStreamReportsMissingSSHPlumbing(t *testing.T) {
	h := newTerminalTestHandler(t, map[int64]*db.VM{11: {
		ID:        11,
		UserID:    7,
		Name:      "hello1",
		Status:    "running",
		Image:     "ubuntu:24.04",
		IPAddress: sql.NullString{String: "10.0.0.2", Valid: true},
		CreatedAt: db.SQLiteTime{Time: time.Now()},
		UpdatedAt: db.SQLiteTime{Time: time.Now()},
	}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/vms/11/terminal/stream", strings.NewReader("input=whoami"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.handleTerminalStream(rec, req, dashboardPrincipal{UserID: 7, Username: "bob", Role: "user"})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if body := rec.Body.String(); !strings.Contains(body, "terminal ssh plumbing is not configured") {
		t.Fatalf("body = %q, want ssh plumbing error", body)
	}
}

func TestRenderTerminalForbidsForeignVM(t *testing.T) {
	h := newTerminalTestHandler(t, map[int64]*db.VM{11: {
		ID:        11,
		UserID:    8,
		Name:      "hello1",
		Status:    "running",
		Image:     "ubuntu:24.04",
		IPAddress: sql.NullString{String: "10.0.0.2", Valid: true},
		CreatedAt: db.SQLiteTime{Time: time.Now()},
		UpdatedAt: db.SQLiteTime{Time: time.Now()},
	}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vms/11/terminal", nil)

	h.renderTerminal(rec, req, dashboardPrincipal{UserID: 7, Username: "bob", Role: "user"})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRenderTerminalShowsInteractiveShell(t *testing.T) {
	h := newTerminalTestHandler(t, map[int64]*db.VM{11: {
		ID:        11,
		UserID:    7,
		Name:      "hello1",
		Status:    "running",
		Image:     "ubuntu:24.04",
		IPAddress: sql.NullString{String: "10.0.0.2", Valid: true},
		CreatedAt: db.SQLiteTime{Time: time.Now()},
		UpdatedAt: db.SQLiteTime{Time: time.Now()},
	}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vms/11/terminal", nil)

	h.renderTerminal(rec, req, dashboardPrincipal{UserID: 7, Username: "bob", Role: "user"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Interactive shell session") {
		t.Fatalf("body = %q, want interactive terminal copy", body)
	}
	if !strings.Contains(body, `terminal\/ws`) {
		t.Fatalf("body = %q, want websocket terminal path", body)
	}
}

func TestShellEscape(t *testing.T) {
	got := shellEscape("echo 'hi'")
	want := `'echo '"'"'hi'"'"''`
	if got != want {
		t.Fatalf("shellEscape() = %q, want %q", got, want)
	}
}

func newTerminalTestHandler(t *testing.T, vms map[int64]*db.VM) *Handler {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := sessionauth.New(
		dashboardUserLookup{user: &sessionauth.AuthUser{ID: 7, Handle: "bob", Role: "user", PasswordBcrypt: string(hash)}},
		"admin",
		string(hash),
		"test_session",
		time.Hour,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(&fireslice.Service{
		Users: &dashboardStubUsers{users: map[int64]*db.User{7: {
			ID:         7,
			Handle:     "bob",
			Email:      "bob@example.com",
			Role:       "user",
			TrustLevel: "member",
			CreatedAt:  db.SQLiteTime{Time: time.Now()},
			UpdatedAt:  db.SQLiteTime{Time: time.Now()},
		}}},
		VMs: &dashboardStubVMs{vms: vms},
	}, auth, map[string]string{"domain": "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
