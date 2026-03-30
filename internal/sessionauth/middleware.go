package sessionauth

import (
	"context"
	"net/http"

	"github.com/mojomast/fireslice/internal/httpapi"
)

type contextKey struct{}

func (m *Manager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(m.cookieName)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		session, ok := m.Session(cookie.Value)
		if !ok {
			m.ClearSessionCookie(w)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, session)
		ctx = httpapi.WithPrincipal(ctx, httpapi.Principal{Subject: session.Username, Role: "admin"})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Manager) RequirePageAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(m.cookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		session, ok := m.Session(cookie.Value)
		if !ok {
			m.ClearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SessionFromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(contextKey{}).(Session)
	return session, ok
}
