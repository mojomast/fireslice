package httpapi

import (
	"net/http"

	"github.com/mojomast/fireslice/internal/db"
)

type createUserRequest struct {
	Handle   string          `json:"handle"`
	Email    string          `json:"email"`
	FirstKey *userKeyRequest `json:"first_key"`
}

type userKeyRequest struct {
	PublicKey string `json:"public_key"`
	Label     string `json:"label"`
}

type userSummary struct {
	ID         int64  `json:"id"`
	Handle     string `json:"handle"`
	Email      string `json:"email"`
	TrustLevel string `json:"trust_level"`
	KeyCount   int    `json:"key_count"`
	VMCount    int    `json:"vm_count"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type userKeyResponse struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label"`
	CreatedAt   string `json:"created_at"`
}

type userDetailResponse struct {
	ID         int64             `json:"id"`
	Handle     string            `json:"handle"`
	Email      string            `json:"email"`
	TrustLevel string            `json:"trust_level"`
	VMCount    int               `json:"vm_count"`
	CreatedAt  string            `json:"created_at"`
	UpdatedAt  string            `json:"updated_at"`
	Keys       []userKeyResponse `json:"keys"`
}

func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if h.service.Users == nil || h.service.VMs == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "user service is unavailable", nil)
		return
	}

	users, err := h.service.Users.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list users", nil)
		return
	}
	vms, err := h.service.VMs.ListVMs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list users", nil)
		return
	}
	stableSortUsers(users)

	vmCounts := map[int64]int{}
	for _, vm := range vms {
		vmCounts[vm.UserID]++
	}

	items := make([]userSummary, 0, len(users))
	for _, user := range users {
		keys, err := h.service.Users.ListSSHKeys(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to list users", nil)
			return
		}
		items = append(items, userToSummary(user, len(keys), vmCounts[user.ID]))
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": items})
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if h.service.Users == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "user service is unavailable", nil)
		return
	}

	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON", nil)
		return
	}

	details := map[string]string{}
	if msg := validateHandle(req.Handle); msg != "" {
		details["handle"] = msg
	}
	if msg := validateEmail(req.Email); msg != "" {
		details["email"] = msg
	}
	if req.FirstKey != nil {
		if msg := validatePublicKey(req.FirstKey.PublicKey); msg != "" {
			details["first_key.public_key"] = msg
		}
		if msg := validateLabel(req.FirstKey.Label); msg != "" {
			details["first_key.label"] = msg
		}
	}
	if len(details) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "validation_failed", "request validation failed", details)
		return
	}

	user, err := h.service.Users.CreateUser(r.Context(), req.Handle, req.Email)
	if err != nil {
		if isConflictError(err) {
			writeError(w, http.StatusConflict, "conflict", "user already exists", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create user", nil)
		return
	}

	keys := []userKeyResponse{}
	if req.FirstKey != nil {
		key, err := h.service.Users.AddSSHKey(r.Context(), user.ID, req.FirstKey.PublicKey, req.FirstKey.Label)
		if err != nil {
			if isConflictError(err) {
				writeError(w, http.StatusConflict, "conflict", "ssh key already exists", nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to add SSH key", nil)
			return
		}
		keys = append(keys, sshKeyToResponse(key))
	}

	if err := h.auditEvent(r.Context(), "user.created", "user", user.ID, user.Handle); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to write audit log", nil)
		return
	}
	if len(keys) > 0 {
		if err := h.auditEvent(r.Context(), "ssh_key.added", "user", user.ID, keys[0].Fingerprint); err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to write audit log", nil)
			return
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"user": map[string]any{
			"id":          user.ID,
			"handle":      user.Handle,
			"email":       user.Email,
			"trust_level": user.TrustLevel,
			"created_at":  formatTime(user.CreatedAt),
			"updated_at":  formatTime(user.UpdatedAt),
			"keys":        keys,
		},
	})
}

func (h *Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	if h.service.Users == nil || h.service.VMs == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "user service is unavailable", nil)
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}

	user, err := h.service.Users.GetUser(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load user", nil)
		return
	}
	keys, err := h.service.Users.ListSSHKeys(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load user", nil)
		return
	}
	vms, err := h.service.VMs.ListVMs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load user", nil)
		return
	}

	keyResponses := make([]userKeyResponse, 0, len(keys))
	vmCount := 0
	for _, key := range keys {
		keyResponses = append(keyResponses, sshKeyToResponse(key))
	}
	for _, vm := range vms {
		if vm.UserID == user.ID {
			vmCount++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": userDetailResponse{
			ID:         user.ID,
			Handle:     user.Handle,
			Email:      user.Email,
			TrustLevel: user.TrustLevel,
			VMCount:    vmCount,
			CreatedAt:  formatTime(user.CreatedAt),
			UpdatedAt:  formatTime(user.UpdatedAt),
			Keys:       keyResponses,
		},
	})
}

func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if h.service.Users == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "user service is unavailable", nil)
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}

	if err := h.service.Users.DeleteUser(r.Context(), id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to delete user", nil)
		return
	}
	if err := h.auditEvent(r.Context(), "user.deleted", "user", id, ""); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to write audit log", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleAddUserKey(w http.ResponseWriter, r *http.Request) {
	if h.service.Users == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "user service is unavailable", nil)
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}

	var req userKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON", nil)
		return
	}

	details := map[string]string{}
	if msg := validatePublicKey(req.PublicKey); msg != "" {
		details["public_key"] = msg
	}
	if msg := validateLabel(req.Label); msg != "" {
		details["label"] = msg
	}
	if len(details) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "validation_failed", "request validation failed", details)
		return
	}

	key, err := h.service.Users.AddSSHKey(r.Context(), id, req.PublicKey, req.Label)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		if isConflictError(err) {
			writeError(w, http.StatusConflict, "conflict", "ssh key already exists", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to add SSH key", nil)
		return
	}
	if err := h.auditEvent(r.Context(), "ssh_key.added", "user", id, key.Fingerprint); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to write audit log", nil)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"key": sshKeyToResponse(key)})
}

func (h *Handler) handleDeleteUserKey(w http.ResponseWriter, r *http.Request) {
	if h.service.Users == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "user service is unavailable", nil)
		return
	}

	userID, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}
	keyID, err := parsePathID(r, "keyID")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}

	if err := h.service.Users.DeleteSSHKey(r.Context(), userID, keyID); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "SSH key not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to delete SSH key", nil)
		return
	}
	if err := h.auditEvent(r.Context(), "ssh_key.deleted", "ssh_key", keyID, ""); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to write audit log", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func userToSummary(user *db.User, keyCount, vmCount int) userSummary {
	return userSummary{
		ID:         user.ID,
		Handle:     user.Handle,
		Email:      user.Email,
		TrustLevel: user.TrustLevel,
		KeyCount:   keyCount,
		VMCount:    vmCount,
		CreatedAt:  formatTime(user.CreatedAt),
		UpdatedAt:  formatTime(user.UpdatedAt),
	}
}

func sshKeyToResponse(key *db.SSHKey) userKeyResponse {
	return userKeyResponse{
		ID:          key.ID,
		UserID:      key.UserID,
		PublicKey:   key.PublicKey,
		Fingerprint: key.Fingerprint,
		Label:       key.Comment,
		CreatedAt:   formatTime(key.CreatedAt),
	}
}
