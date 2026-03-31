package dashboard

import (
	"context"
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

func TestLoginPageRendersAndRedirects(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := sessionauth.New(nil, "admin", string(hash), "test_session", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(&fireslice.Service{}, auth, map[string]string{"domain": "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Routes(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
}

func TestUserDashboardSettingsAndAccountAccess(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := sessionauth.New(dashboardUserLookup{user: &sessionauth.AuthUser{ID: 7, Handle: "bob", Role: "user", PasswordBcrypt: string(hash)}}, "admin", string(hash), "test_session", time.Hour, false)
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
		VMs:    &dashboardStubVMs{},
		Images: dashboardStubImages{images: []fireslice.ImageCatalogEntry{{Name: "ussyuntu", Ref: "ussyuntu", Description: "Default image"}}},
	}, auth, map[string]string{"domain": "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Routes(mux)

	token, err := auth.Login("bob", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	auth.SetSessionCookie(rec, token)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}

	t.Run("settings page remains accessible", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/settings", nil)
		req.AddCookie(cookies[0])
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Account settings for bob") {
			t.Fatalf("settings body missing account marker: %s", body)
		}
		if strings.Contains(body, ">Users<") {
			t.Fatalf("settings body should not include admin nav link: %s", body)
		}
		if !strings.Contains(body, "href=\"/users/7\">Account<") {
			t.Fatalf("settings body missing account nav link: %s", body)
		}
	})

	t.Run("users listing redirects to own account", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.AddCookie(cookies[0])
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
		}
		if location := rec.Header().Get("Location"); location != "/users/7" {
			t.Fatalf("location = %q, want /users/7", location)
		}
	})

	t.Run("vm create page shows image select", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/vms/new", nil)
		req.AddCookie(cookies[0])
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "<select name=\"image\" required>") {
			t.Fatalf("vm new page missing image select: %s", body)
		}
		if !strings.Contains(body, "ussyuntu - ussyuntu") {
			t.Fatalf("vm new page missing image option: %s", body)
		}
	})
}

type dashboardUserLookup struct {
	user *sessionauth.AuthUser
}

func (l dashboardUserLookup) GetUserByHandle(handle string) (*sessionauth.AuthUser, error) {
	if l.user != nil && l.user.Handle == handle {
		copy := *l.user
		return &copy, nil
	}
	return nil, sql.ErrNoRows
}

type dashboardStubUsers struct {
	users map[int64]*db.User
}

func (s *dashboardStubUsers) CreateUser(context.Context, string, string, string, string) (*db.User, error) {
	return nil, nil
}

func (s *dashboardStubUsers) GetUser(_ context.Context, id int64) (*db.User, error) {
	user, ok := s.users[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	copy := *user
	return &copy, nil
}

func (s *dashboardStubUsers) GetUserByHandle(context.Context, string) (*db.User, error) {
	return nil, nil
}
func (s *dashboardStubUsers) ListUsers(context.Context) ([]*db.User, error)       { return nil, nil }
func (s *dashboardStubUsers) DeleteUser(context.Context, int64) error             { return nil }
func (s *dashboardStubUsers) UpdatePassword(context.Context, int64, string) error { return nil }
func (s *dashboardStubUsers) UpdateQuotas(context.Context, int64, string, int, int, int, int) error {
	return nil
}
func (s *dashboardStubUsers) AddSSHKey(context.Context, int64, string, string) (*db.SSHKey, error) {
	return nil, nil
}
func (s *dashboardStubUsers) DeleteSSHKey(context.Context, int64, int64) error { return nil }
func (s *dashboardStubUsers) ListSSHKeys(context.Context, int64) ([]*db.SSHKey, error) {
	return []*db.SSHKey{}, nil
}

type dashboardStubVMs struct{}

type dashboardStubImages struct{ images []fireslice.ImageCatalogEntry }

func (s dashboardStubImages) ListImages(context.Context) ([]fireslice.ImageCatalogEntry, error) {
	return s.images, nil
}
func (s dashboardStubImages) AddImage(context.Context, fireslice.ImageCatalogEntry) error { return nil }
func (s dashboardStubImages) DeleteImage(context.Context, string) error                   { return nil }

func (s *dashboardStubVMs) CreateVMRecord(context.Context, fireslice.CreateVMInput) (*db.VM, error) {
	return nil, nil
}
func (s *dashboardStubVMs) GetVM(context.Context, int64) (*db.VM, error) { return nil, nil }
func (s *dashboardStubVMs) ListVMs(context.Context) ([]*db.VM, error)    { return []*db.VM{}, nil }
func (s *dashboardStubVMs) ListVMsByUser(context.Context, int64) ([]*db.VM, error) {
	return []*db.VM{}, nil
}
func (s *dashboardStubVMs) UpdateVMStatus(context.Context, int64, string) error { return nil }
func (s *dashboardStubVMs) UpdateVMExposure(context.Context, int64, bool, string, int) error {
	return nil
}
func (s *dashboardStubVMs) DeleteVM(context.Context, int64) error { return nil }
