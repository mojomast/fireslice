package dashboard

import (
	"context"
	"embed"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/fireslice"
	"github.com/mojomast/fireslice/internal/sessionauth"
)

//go:embed templates/* static/*
var fs embed.FS

type Handler struct {
	templates *template.Template
	service   *fireslice.Service
	auth      *sessionauth.Manager
	config    map[string]string
	style     []byte
}

type dashboardPrincipal struct {
	UserID   int64
	Username string
	Role     string
}

func New(service *fireslice.Service, auth *sessionauth.Manager, config map[string]string) (*Handler, error) {
	tmpl, err := template.ParseFS(fs, "templates/*.html")
	if err != nil {
		return nil, err
	}
	style, err := fs.ReadFile("static/style.css")
	if err != nil {
		return nil, err
	}
	return &Handler{templates: tmpl, service: service, auth: auth, config: config, style: style}, nil
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /dashboard/static/style.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(h.style)
	})
	mux.HandleFunc("GET /login", h.handleLoginPage)
	mux.HandleFunc("POST /login", h.handleLoginPost)
	mux.HandleFunc("POST /logout", h.handleLogout)

	protected := h.auth.RequirePageAuth(http.HandlerFunc(h.routeProtected))
	mux.Handle("GET /", protected)
	mux.Handle("GET /users", protected)
	mux.Handle("GET /users/{id}", protected)
	mux.Handle("GET /vms/new", protected)
	mux.Handle("GET /settings", protected)
	mux.Handle("POST /users", protected)
	mux.Handle("POST /users/{id}/keys", protected)
	mux.Handle("POST /users/{id}/delete", protected)
	mux.Handle("POST /users/{id}/password", protected)
	mux.Handle("POST /vms", protected)
	mux.Handle("POST /vms/{id}/start", protected)
	mux.Handle("POST /vms/{id}/stop", protected)
	mux.Handle("POST /vms/{id}/delete", protected)
	mux.Handle("POST /vms/{id}/expose", protected)
	mux.Handle("POST /vms/{id}/hide", protected)
}

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	_ = h.templates.ExecuteTemplate(w, "login.html", map[string]any{"Error": r.URL.Query().Get("error")})
}

func (h *Handler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=invalid+form", http.StatusSeeOther)
		return
	}
	token, err := h.auth.Login(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		http.Redirect(w, r, "/login?error=invalid+credentials", http.StatusSeeOther)
		return
	}
	h.auth.SetSessionCookie(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(h.auth.CookieName()); err == nil {
		h.auth.Logout(cookie.Value)
	}
	h.auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) routeProtected(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principalFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		h.renderIndex(w, r, principal, "")
	case r.Method == http.MethodGet && r.URL.Path == "/users":
		h.renderUsers(w, r, principal, "")
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/users/"):
		h.renderUserDetail(w, r, principal, "")
	case r.Method == http.MethodGet && r.URL.Path == "/vms/new":
		h.renderVMNew(w, r, principal, "")
	case r.Method == http.MethodGet && r.URL.Path == "/settings":
		h.renderSettings(w, r, principal)
	case r.Method == http.MethodPost:
		h.handleAction(w, r, principal)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) renderIndex(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal, errMsg string) {
	vms, err := h.visibleVMs(r.Context(), principal)
	if err != nil {
		h.renderError(w, err.Error())
		return
	}
	rows := make([]map[string]any, 0, len(vms))
	for _, vm := range vms {
		owner := principal.Username
		if principal.Role == "admin" {
			if user, err := h.service.Users.GetUser(r.Context(), vm.UserID); err == nil {
				owner = user.Handle
			}
		}
		rows = append(rows, map[string]any{
			"id":           vm.ID,
			"name":         vm.Name,
			"user_handle":  owner,
			"status":       vm.Status,
			"ip_address":   vm.IPAddress.String,
			"subdomain":    vm.Subdomain.String,
			"exposed_port": vm.ExposedPort,
			"created_at":   vm.CreatedAt.Time.Format("2006-01-02 15:04"),
		})
	}
	_ = h.templates.ExecuteTemplate(w, "index.html", map[string]any{"VMs": rows, "Error": errMsg, "Principal": principal, "IsAdmin": principal.Role == "admin"})
}

func (h *Handler) renderUsers(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal, errMsg string) {
	if principal.Role != "admin" {
		http.Redirect(w, r, "/users/"+strconv.FormatInt(principal.UserID, 10), http.StatusSeeOther)
		return
	}
	users, err := h.service.Users.ListUsers(r.Context())
	if err != nil {
		h.renderError(w, err.Error())
		return
	}
	vms, _ := h.service.VMs.ListVMs(r.Context())
	rows := make([]map[string]any, 0, len(users))
	for _, user := range users {
		keys, _ := h.service.Users.ListSSHKeys(r.Context(), user.ID)
		vmCount := 0
		for _, vm := range vms {
			if vm.UserID == user.ID {
				vmCount++
			}
		}
		rows = append(rows, map[string]any{
			"id":          user.ID,
			"handle":      user.Handle,
			"email":       user.Email,
			"role":        user.Role,
			"trust_level": user.TrustLevel,
			"key_count":   len(keys),
			"vm_count":    vmCount,
			"created_at":  user.CreatedAt.Time.Format("2006-01-02 15:04"),
		})
	}
	_ = h.templates.ExecuteTemplate(w, "users.html", map[string]any{"Users": rows, "Error": errMsg, "Principal": principal, "IsAdmin": true})
}

func (h *Handler) renderUserDetail(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal, errMsg string) {
	id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/users/"), 10, 64)
	if principal.Role != "admin" {
		id = principal.UserID
	}
	user, err := h.service.Users.GetUser(r.Context(), id)
	if err != nil {
		h.renderError(w, err.Error())
		return
	}
	keys, _ := h.service.Users.ListSSHKeys(r.Context(), id)
	vms, _ := h.service.VMs.ListVMsByUser(r.Context(), id)
	keyRows := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		keyRows = append(keyRows, map[string]any{"label": key.Comment, "fingerprint": key.Fingerprint, "created_at": key.CreatedAt.Time.Format("2006-01-02 15:04")})
	}
	vmRows := make([]map[string]any, 0, len(vms))
	for _, vm := range vms {
		vmRows = append(vmRows, map[string]any{"name": vm.Name, "status": vm.Status, "subdomain": vm.Subdomain.String})
	}
	_ = h.templates.ExecuteTemplate(w, "user_detail.html", map[string]any{"User": map[string]any{"id": user.ID, "handle": user.Handle, "email": user.Email, "role": user.Role, "trust_level": user.TrustLevel, "keys": keyRows}, "VMs": vmRows, "Error": errMsg, "Principal": principal, "IsAdmin": principal.Role == "admin", "Self": principal.UserID == user.ID})
}

func (h *Handler) renderVMNew(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal, errMsg string) {
	rows := []map[string]any{}
	if principal.Role == "admin" {
		users, err := h.service.Users.ListUsers(r.Context())
		if err != nil {
			h.renderError(w, err.Error())
			return
		}
		for _, user := range users {
			rows = append(rows, map[string]any{"id": user.ID, "handle": user.Handle})
		}
	} else {
		rows = append(rows, map[string]any{"id": principal.UserID, "handle": principal.Username})
	}
	_ = h.templates.ExecuteTemplate(w, "vm_new.html", map[string]any{"Users": rows, "Error": errMsg, "Principal": principal, "IsAdmin": principal.Role == "admin"})
}

func (h *Handler) renderSettings(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal) {
	if principal.Role == "admin" {
		_ = h.templates.ExecuteTemplate(w, "settings.html", map[string]any{"Config": h.config, "Principal": principal, "IsAdmin": true})
		return
	}
	user, err := h.service.Users.GetUser(r.Context(), principal.UserID)
	if err != nil {
		h.renderError(w, err.Error())
		return
	}
	_ = h.templates.ExecuteTemplate(w, "settings.html", map[string]any{"Config": map[string]string{"handle": user.Handle, "email": user.Email, "role": user.Role, "trust_level": user.TrustLevel}, "Principal": principal, "IsAdmin": false})
}

func (h *Handler) handleAction(w http.ResponseWriter, r *http.Request, principal dashboardPrincipal) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, err.Error())
		return
	}
	path := r.URL.Path
	ctx := r.Context()
	redirectTo := "/"

	switch {
	case path == "/users" && principal.Role == "admin":
		_, err := h.service.Users.CreateUser(ctx, r.FormValue("handle"), r.FormValue("email"), r.FormValue("password"), r.FormValue("role"))
		if err != nil {
			h.renderUsers(w, r, principal, err.Error())
			return
		}
		redirectTo = "/users"
	case strings.HasSuffix(path, "/keys") && strings.HasPrefix(path, "/users/"):
		id := h.authorizedUserID(strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/keys"), principal)
		if id == 0 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, err := h.service.Users.AddSSHKey(ctx, id, r.FormValue("public_key"), r.FormValue("label"))
		if err != nil {
			h.renderUserDetail(w, r, principal, err.Error())
			return
		}
		redirectTo = "/users/" + strconv.FormatInt(id, 10)
	case strings.HasSuffix(path, "/password") && strings.HasPrefix(path, "/users/"):
		id := h.authorizedUserID(strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/password"), principal)
		if id == 0 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := h.service.Users.UpdatePassword(ctx, id, r.FormValue("password")); err != nil {
			h.renderUserDetail(w, r, principal, err.Error())
			return
		}
		redirectTo = "/users/" + strconv.FormatInt(id, 10)
	case strings.HasSuffix(path, "/delete") && strings.HasPrefix(path, "/users/") && principal.Role == "admin":
		id, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/delete"), 10, 64)
		if err := h.service.Users.DeleteUser(ctx, id); err != nil {
			h.renderUsers(w, r, principal, err.Error())
			return
		}
		redirectTo = "/users"
	case path == "/vms":
		userID := principal.UserID
		if principal.Role == "admin" {
			userID, _ = strconv.ParseInt(r.FormValue("user_id"), 10, 64)
		}
		vcpu, _ := strconv.Atoi(r.FormValue("vcpu"))
		memoryMB, _ := strconv.Atoi(r.FormValue("memory_mb"))
		diskGB, _ := strconv.Atoi(r.FormValue("disk_gb"))
		exposedPort, _ := strconv.Atoi(r.FormValue("exposed_port"))
		_, err := h.service.CreateVM(ctx, fireslice.CreateVMInput{
			UserID:          userID,
			Name:            r.FormValue("name"),
			Image:           r.FormValue("image"),
			VCPU:            vcpu,
			MemoryMB:        memoryMB,
			DiskGB:          diskGB,
			ExposeSubdomain: r.FormValue("expose_subdomain") == "on",
			Subdomain:       r.FormValue("subdomain"),
			ExposedPort:     exposedPort,
		})
		if err != nil {
			h.renderVMNew(w, r, principal, err.Error())
			return
		}
	case strings.HasSuffix(path, "/start") && strings.HasPrefix(path, "/vms/"):
		id := vmIDFromPath(path, "/start")
		if !h.canManageVM(ctx, id, principal) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := h.service.StartVM(ctx, id); err != nil {
			h.renderIndex(w, r, principal, err.Error())
			return
		}
	case strings.HasSuffix(path, "/stop") && strings.HasPrefix(path, "/vms/"):
		id := vmIDFromPath(path, "/stop")
		if !h.canManageVM(ctx, id, principal) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := h.service.StopVM(ctx, id); err != nil {
			h.renderIndex(w, r, principal, err.Error())
			return
		}
	case strings.HasSuffix(path, "/delete") && strings.HasPrefix(path, "/vms/"):
		id := vmIDFromPath(path, "/delete")
		if !h.canManageVM(ctx, id, principal) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := h.service.DestroyVM(ctx, id); err != nil {
			h.renderIndex(w, r, principal, err.Error())
			return
		}
	case strings.HasSuffix(path, "/expose") && strings.HasPrefix(path, "/vms/"):
		id := vmIDFromPath(path, "/expose")
		if !h.canManageVM(ctx, id, principal) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		port, _ := strconv.Atoi(r.FormValue("exposed_port"))
		if err := h.service.ExposeVM(ctx, id, r.FormValue("subdomain"), port); err != nil {
			h.renderIndex(w, r, principal, err.Error())
			return
		}
	case strings.HasSuffix(path, "/hide") && strings.HasPrefix(path, "/vms/"):
		id := vmIDFromPath(path, "/hide")
		if !h.canManageVM(ctx, id, principal) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := h.service.HideVM(ctx, id); err != nil {
			h.renderIndex(w, r, principal, err.Error())
			return
		}
	default:
		http.NotFound(w, r)
		return
	}

	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

func (h *Handler) renderError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadGateway)
	_ = h.templates.ExecuteTemplate(w, "error.html", map[string]any{"Error": msg})
}

func vmIDFromPath(path, suffix string) int64 {
	id, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(path, "/vms/"), suffix), 10, 64)
	return id
}

func (h *Handler) principalFromRequest(r *http.Request) (dashboardPrincipal, bool) {
	session, ok := sessionauth.SessionFromContext(r.Context())
	if !ok {
		return dashboardPrincipal{}, false
	}
	return dashboardPrincipal{UserID: session.UserID, Username: session.Username, Role: session.Role}, true
}

func (h *Handler) visibleVMs(ctx context.Context, principal dashboardPrincipal) ([]*db.VM, error) {
	requestCtx := ctx
	if principal.Role == "admin" {
		return h.service.VMs.ListVMs(requestCtx)
	}
	return h.service.VMs.ListVMsByUser(requestCtx, principal.UserID)
}

func (h *Handler) authorizedUserID(raw string, principal dashboardPrincipal) int64 {
	id, _ := strconv.ParseInt(raw, 10, 64)
	if principal.Role == "admin" {
		return id
	}
	if id == principal.UserID {
		return id
	}
	return 0
}

func (h *Handler) canManageVM(ctx context.Context, vmID int64, principal dashboardPrincipal) bool {
	requestCtx := ctx
	if principal.Role == "admin" {
		return true
	}
	vm, err := h.service.VMs.GetVM(requestCtx, vmID)
	if err != nil {
		return false
	}
	return vm.UserID == principal.UserID
}
