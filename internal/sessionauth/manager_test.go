package sessionauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestManagerLoginLogoutAndMiddleware(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := New("admin", string(hash), "test_session", time.Hour, false)
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
