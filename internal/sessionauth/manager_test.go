package sessionauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/mojomast/fireslice/internal/db"
	"golang.org/x/crypto/bcrypt"
)

func TestManagerLoginLogoutAndMiddleware(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := New(nil, "admin", string(hash), "test_session", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("invalid password", func(t *testing.T) {
		if _, err := mgr.Login("admin", "wrong"); err == nil {
			t.Fatal("expected login failure")
		}
	})

	token, err := mgr.Login("admin", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mgr.Session(token); !ok {
		t.Fatal("expected session to exist")
	}

	rec := httptest.NewRecorder()
	mgr.SetSessionCookie(rec, token)
	res := rec.Result()
	if len(res.Cookies()) != 1 {
		t.Fatalf("cookies = %d, want 1", len(res.Cookies()))
	}

	protected := mgr.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("protected route authorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(res.Cookies()[0])
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})

	t.Run("protected route unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	mgr.Logout(token)
	if _, ok := mgr.Session(token); ok {
		t.Fatal("expected session to be deleted")
	}
}

func TestManagerDBBackedLoginAndPasswordRotation(t *testing.T) {
	f, err := os.CreateTemp("", "fireslice-sessionauth-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)
	defer os.Remove(path + "-wal")
	defer os.Remove(path + "-shm")

	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	ctx := context.Background()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	user, err := database.CreateFiresliceUser(ctx, "bob", "bob@example.com", "old-password", "user")
	if err != nil {
		t.Fatal(err)
	}

	bootstrapHash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := New(&DBLookup{DB: database}, "admin", string(bootstrapHash), "test_session", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}

	token, err := mgr.Login("bob", "old-password")
	if err != nil {
		t.Fatalf("login with original password: %v", err)
	}
	session, ok := mgr.Session(token)
	if !ok {
		t.Fatal("expected session to exist")
	}
	if session.UserID != user.ID {
		t.Fatalf("session user id = %d, want %d", session.UserID, user.ID)
	}
	if session.Role != "user" {
		t.Fatalf("session role = %q, want user", session.Role)
	}

	if err := database.UpdateFiresliceUserPassword(ctx, user.ID, "new-password"); err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.Login("bob", "old-password"); err == nil {
		t.Fatal("expected old password login to fail")
	}
	if _, err := mgr.Login("bob", "new-password"); err != nil {
		t.Fatalf("login with updated password: %v", err)
	}
}
