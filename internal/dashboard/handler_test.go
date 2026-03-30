package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mojomast/fireslice/internal/fireslice"
	"github.com/mojomast/fireslice/internal/sessionauth"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginPageRendersAndRedirects(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := sessionauth.New("admin", string(hash), "test_session", time.Hour, false)
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
