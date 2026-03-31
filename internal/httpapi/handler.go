package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/fireslice"
	gossh "golang.org/x/crypto/ssh"
)

const basePath = "/api/admin"

var (
	handlePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	subdomainPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

type AuditLogger interface {
	LogAudit(ctx context.Context, action, targetType string, targetID int64, detail string) error
}

type VMExposureReader interface {
	GetVMExposure(ctx context.Context, id int64) (fireslice.VMExposure, error)
}

type Options struct {
	AuthMiddleware AuthMiddleware
	AuditLogger    AuditLogger
}

type Handler struct {
	service *fireslice.Service
	auth    AuthMiddleware
	audit   AuditLogger
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

func New(service *fireslice.Service, opts Options) *Handler {
	if service == nil {
		service = &fireslice.Service{}
	}
	return &Handler{
		service: service,
		auth:    opts.AuthMiddleware,
		audit:   opts.AuditLogger,
	}
}

func (h *Handler) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	h.Routes(mux)
	return mux
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.Handle("GET "+basePath+"/health", h.withAuth(http.HandlerFunc(h.handleHealth)))
	mux.Handle("GET "+basePath+"/users", h.withAuth(http.HandlerFunc(h.handleListUsers)))
	mux.Handle("POST "+basePath+"/users", h.withAuth(http.HandlerFunc(h.handleCreateUser)))
	mux.Handle("GET "+basePath+"/users/{id}", h.withAuth(http.HandlerFunc(h.handleGetUser)))
	mux.Handle("DELETE "+basePath+"/users/{id}", h.withAuth(http.HandlerFunc(h.handleDeleteUser)))
	mux.Handle("POST "+basePath+"/users/{id}/keys", h.withAuth(http.HandlerFunc(h.handleAddUserKey)))
	mux.Handle("DELETE "+basePath+"/users/{id}/keys/{keyID}", h.withAuth(http.HandlerFunc(h.handleDeleteUserKey)))
	mux.Handle("POST "+basePath+"/users/{id}/password", h.withAuth(http.HandlerFunc(h.handleUpdateUserPassword)))
	mux.Handle("PATCH "+basePath+"/users/{id}/quotas", h.withAuth(http.HandlerFunc(h.handleUpdateUserQuotas)))
	mux.Handle("GET "+basePath+"/vms", h.withAuth(http.HandlerFunc(h.handleListVMs)))
	mux.Handle("POST "+basePath+"/vms", h.withAuth(http.HandlerFunc(h.handleCreateVM)))
	mux.Handle("GET "+basePath+"/vms/{id}", h.withAuth(http.HandlerFunc(h.handleGetVM)))
	mux.Handle("POST "+basePath+"/vms/{id}/start", h.withAuth(http.HandlerFunc(h.handleStartVM)))
	mux.Handle("POST "+basePath+"/vms/{id}/stop", h.withAuth(http.HandlerFunc(h.handleStopVM)))
	mux.Handle("DELETE "+basePath+"/vms/{id}", h.withAuth(http.HandlerFunc(h.handleDeleteVM)))
	mux.Handle("PATCH "+basePath+"/vms/{id}/exposure", h.withAuth(http.HandlerFunc(h.handlePatchVMExposure)))
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string, details map[string]string) {
	writeJSON(w, status, errorEnvelope{Error: apiError{Code: code, Message: message, Details: details}})
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func parsePathID(r *http.Request, key string) (int64, error) {
	value := r.PathValue(key)
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid %s", key)
	}
	return id, nil
}

func validateHandle(handle string) string {
	handle = strings.TrimSpace(handle)
	if handle == "" || len(handle) > 64 || !handlePattern.MatchString(handle) {
		return "handle must contain only lowercase letters, digits, or hyphens"
	}
	return ""
}

func validateEmail(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "email must be a valid address"
	}
	return ""
}

func validateLabel(label string) string {
	if strings.TrimSpace(label) == "" {
		return "label is required"
	}
	return ""
}

func validatePublicKey(publicKey string) string {
	if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey))); err != nil {
		return "public_key must be a valid authorized_keys entry"
	}
	return ""
}

func validatePort(port int) string {
	if port < 1 || port > 65535 {
		return "exposed_port must be between 1 and 65535"
	}
	return ""
}

func validateSubdomain(subdomain string) string {
	subdomain = strings.TrimSpace(subdomain)
	if subdomain == "" || len(subdomain) > 63 || !subdomainPattern.MatchString(subdomain) {
		return "subdomain must contain only lowercase letters, digits, or hyphens"
	}
	return ""
}

func validateVMName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || !subdomainPattern.MatchString(name) {
		return "name must contain only lowercase letters, digits, or hyphens"
	}
	return ""
}

func isConflictError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "duplicate") || strings.Contains(message, "already exists")
}

func isNotFound(err error) bool {
	return fireslice.IsNotFound(err)
}

func formatTime(t db.SQLiteTime) string {
	if t.IsZero() {
		return ""
	}
	return t.Time.UTC().Format("2006-01-02T15:04:05Z")
}

func stringPtrFromNull(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	copy := value.String
	return &copy
}

func int64PtrFromNull(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	copy := value.Int64
	return &copy
}

func stableSortUsers(users []*db.User) {
	sort.Slice(users, func(i, j int) bool {
		if users[i].Handle == users[j].Handle {
			return users[i].ID < users[j].ID
		}
		return users[i].Handle < users[j].Handle
	})
}

func stableSortVMs(vms []*db.VM) {
	sort.Slice(vms, func(i, j int) bool {
		if vms[i].Name == vms[j].Name {
			return vms[i].ID < vms[j].ID
		}
		return vms[i].Name < vms[j].Name
	})
}

func (h *Handler) auditEvent(ctx context.Context, action, targetType string, targetID int64, detail string) error {
	if h.audit == nil {
		return nil
	}
	return h.audit.LogAudit(ctx, action, targetType, targetID, detail)
}

func (h *Handler) lookupExposure(ctx context.Context, id int64) (fireslice.VMExposure, error) {
	reader, ok := h.service.VMs.(VMExposureReader)
	if !ok {
		return fireslice.VMExposure{}, nil
	}
	return reader.GetVMExposure(ctx, id)
}
