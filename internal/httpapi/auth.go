package httpapi

import (
	"context"
	"net/http"
)

type AuthMiddleware func(http.Handler) http.Handler

type Principal struct {
	Subject string `json:"subject"`
	UserID  int64  `json:"user_id,omitempty"`
	Role    string `json:"role,omitempty"`
}

type principalContextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func (h *Handler) withAuth(next http.Handler) http.Handler {
	if h.auth == nil {
		return next
	}
	return h.auth(next)
}
