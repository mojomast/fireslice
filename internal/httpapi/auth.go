package httpapi

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/mojomast/fireslice/internal/db"
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

func principalFromRequest(r *http.Request) (Principal, bool) {
	return PrincipalFromContext(r.Context())
}

func requirePrincipal(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	principal, ok := principalFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return Principal{}, false
	}
	return principal, true
}

func isAdmin(principal Principal) bool {
	return principal.Role == "admin"
}

func authorizeUserAccess(w http.ResponseWriter, principal Principal, userID int64) bool {
	if isAdmin(principal) || principal.UserID == userID {
		return true
	}
	writeError(w, http.StatusForbidden, "forbidden", "forbidden", nil)
	return false
}

func (h *Handler) authorizeVMAccess(w http.ResponseWriter, r *http.Request, principal Principal, vmID int64) (*db.VM, bool) {
	if h.service.VMs == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM service is unavailable", nil)
		return nil, false
	}
	vmRecord, err := h.service.VMs.GetVM(r.Context(), vmID)
	if err != nil {
		if err == sql.ErrNoRows || isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "VM not found", nil)
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load VM", nil)
		return nil, false
	}
	if isAdmin(principal) || vmRecord.UserID == principal.UserID {
		return vmRecord, true
	}
	writeError(w, http.StatusForbidden, "forbidden", "forbidden", nil)
	return nil, false
}
