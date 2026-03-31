package httpapi

import (
	"net/http"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/fireslice"
)

type createVMRequest struct {
	UserID          int64   `json:"user_id"`
	Name            string  `json:"name"`
	Image           string  `json:"image"`
	VCPU            int     `json:"vcpu"`
	MemoryMB        int     `json:"memory_mb"`
	DiskGB          int     `json:"disk_gb"`
	ExposeSubdomain bool    `json:"expose_subdomain"`
	Subdomain       *string `json:"subdomain"`
	ExposedPort     int     `json:"exposed_port"`
}

type patchExposureRequest struct {
	ExposeSubdomain bool    `json:"expose_subdomain"`
	Subdomain       *string `json:"subdomain"`
	ExposedPort     int     `json:"exposed_port"`
}

type vmResponse struct {
	ID              int64   `json:"id"`
	UserID          int64   `json:"user_id"`
	UserHandle      string  `json:"user_handle,omitempty"`
	Name            string  `json:"name"`
	Status          string  `json:"status"`
	Image           string  `json:"image"`
	VCPU            int     `json:"vcpu"`
	MemoryMB        int     `json:"memory_mb"`
	DiskGB          int     `json:"disk_gb"`
	IPAddress       *string `json:"ip_address"`
	TapDevice       *string `json:"tap_device"`
	MACAddress      *string `json:"mac_address"`
	PID             *int64  `json:"pid"`
	ExposeSubdomain bool    `json:"expose_subdomain"`
	Subdomain       string  `json:"subdomain,omitempty"`
	ExposedPort     int     `json:"exposed_port"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

func (h *Handler) handleListVMs(w http.ResponseWriter, r *http.Request) {
	if h.service.VMs == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM service is unavailable", nil)
		return
	}
	principal, ok := requirePrincipal(w, r)
	if !ok {
		return
	}

	var (
		vms []*db.VM
		err error
	)
	if isAdmin(principal) {
		vms, err = h.service.VMs.ListVMs(r.Context())
	} else {
		vms, err = h.service.VMs.ListVMsByUser(r.Context(), principal.UserID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list VMs", nil)
		return
	}
	stableSortVMs(vms)

	userHandles := map[int64]string{}
	if h.service.Users != nil {
		for _, vm := range vms {
			if _, ok := userHandles[vm.UserID]; ok {
				continue
			}
			user, err := h.service.Users.GetUser(r.Context(), vm.UserID)
			if err == nil {
				userHandles[vm.UserID] = user.Handle
			}
		}
	}

	items := make([]vmResponse, 0, len(vms))
	for _, vm := range vms {
		exposure, err := h.lookupExposure(r.Context(), vm.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to list VMs", nil)
			return
		}
		items = append(items, vmToResponse(vm, userHandles[vm.UserID], exposure))
	}

	writeJSON(w, http.StatusOK, map[string]any{"vms": items})
}

func (h *Handler) handleCreateVM(w http.ResponseWriter, r *http.Request) {
	if h.service.VMs == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM service is unavailable", nil)
		return
	}
	principal, ok := requirePrincipal(w, r)
	if !ok {
		return
	}

	var req createVMRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON", nil)
		return
	}

	details := map[string]string{}
	if isAdmin(principal) {
		if req.UserID <= 0 {
			details["user_id"] = "user_id must be greater than zero"
		}
	} else {
		req.UserID = principal.UserID
	}
	if msg := validateVMName(req.Name); msg != "" {
		details["name"] = msg
	}
	if req.Image == "" {
		details["image"] = "image is required"
	}
	if req.VCPU <= 0 {
		details["vcpu"] = "vcpu must be greater than zero"
	}
	if req.MemoryMB <= 0 {
		details["memory_mb"] = "memory_mb must be greater than zero"
	}
	if req.DiskGB <= 0 {
		details["disk_gb"] = "disk_gb must be greater than zero"
	}
	subdomain := ""
	if req.Subdomain != nil {
		subdomain = *req.Subdomain
	}
	if req.ExposeSubdomain {
		if msg := validateSubdomain(subdomain); msg != "" {
			details["subdomain"] = msg
		}
		if msg := validatePort(req.ExposedPort); msg != "" {
			details["exposed_port"] = msg
		}
	} else if req.ExposedPort != 0 {
		if msg := validatePort(req.ExposedPort); msg != "" {
			details["exposed_port"] = msg
		}
	}
	if len(details) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "validation_failed", "request validation failed", details)
		return
	}

	vm, err := h.service.CreateVM(r.Context(), fireslice.CreateVMInput{
		UserID:          req.UserID,
		Name:            req.Name,
		Image:           req.Image,
		VCPU:            req.VCPU,
		MemoryMB:        req.MemoryMB,
		DiskGB:          req.DiskGB,
		ExposeSubdomain: req.ExposeSubdomain,
		Subdomain:       subdomain,
		ExposedPort:     req.ExposedPort,
	})
	if err != nil {
		if isConflictError(err) {
			writeError(w, http.StatusConflict, "conflict", "VM name or subdomain already exists", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create VM", nil)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"vm": vmToResponse(vm, "", fireslice.VMExposure{
		ExposeSubdomain: vm.ExposeSubdomain,
		Subdomain:       vm.Subdomain.String,
		ExposedPort:     vm.ExposedPort,
	})})
}

func (h *Handler) handleGetVM(w http.ResponseWriter, r *http.Request) {
	if h.service.VMs == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM service is unavailable", nil)
		return
	}
	principal, ok := requirePrincipal(w, r)
	if !ok {
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}
	vm, ok := h.authorizeVMAccess(w, r, principal, id)
	if !ok {
		return
	}
	exposure, err := h.lookupExposure(r.Context(), vm.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load VM", nil)
		return
	}
	userHandle := ""
	if h.service.Users != nil {
		user, err := h.service.Users.GetUser(r.Context(), vm.UserID)
		if err == nil {
			userHandle = user.Handle
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"vm": vmToResponse(vm, userHandle, exposure)})
}

func (h *Handler) handleStartVM(w http.ResponseWriter, r *http.Request) {
	if h.service.VMs == nil || h.service.VMRun == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM runtime is unavailable", nil)
		return
	}
	principal, ok := requirePrincipal(w, r)
	if !ok {
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}
	if _, ok := h.authorizeVMAccess(w, r, principal, id); !ok {
		return
	}
	if err := h.service.StartVM(r.Context(), id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "VM not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to start VM", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleStopVM(w http.ResponseWriter, r *http.Request) {
	if h.service.VMs == nil || h.service.VMRun == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM runtime is unavailable", nil)
		return
	}
	principal, ok := requirePrincipal(w, r)
	if !ok {
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}
	if _, ok := h.authorizeVMAccess(w, r, principal, id); !ok {
		return
	}
	if err := h.service.StopVM(r.Context(), id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "VM not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to stop VM", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleDeleteVM(w http.ResponseWriter, r *http.Request) {
	if h.service.VMs == nil || h.service.VMRun == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM runtime is unavailable", nil)
		return
	}
	principal, ok := requirePrincipal(w, r)
	if !ok {
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}
	if _, ok := h.authorizeVMAccess(w, r, principal, id); !ok {
		return
	}
	if err := h.service.DestroyVM(r.Context(), id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "VM not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to destroy VM", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handlePatchVMExposure(w http.ResponseWriter, r *http.Request) {
	if h.service.VMs == nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "VM service is unavailable", nil)
		return
	}
	principal, ok := requirePrincipal(w, r)
	if !ok {
		return
	}

	id, err := parsePathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error(), nil)
		return
	}
	if _, ok := h.authorizeVMAccess(w, r, principal, id); !ok {
		return
	}
	var req patchExposureRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON", nil)
		return
	}

	details := map[string]string{}
	subdomain := ""
	if req.Subdomain != nil {
		subdomain = *req.Subdomain
	}
	if req.ExposeSubdomain {
		if msg := validateSubdomain(subdomain); msg != "" {
			details["subdomain"] = msg
		}
		if msg := validatePort(req.ExposedPort); msg != "" {
			details["exposed_port"] = msg
		}
	} else {
		if req.ExposedPort != 0 {
			if msg := validatePort(req.ExposedPort); msg != "" {
				details["exposed_port"] = msg
			}
		}
	}
	if len(details) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "validation_failed", "request validation failed", details)
		return
	}

	var updateErr error
	if req.ExposeSubdomain {
		updateErr = h.service.ExposeVM(r.Context(), id, subdomain, req.ExposedPort)
	} else {
		updateErr = h.service.HideVM(r.Context(), id)
	}
	if updateErr != nil {
		if isNotFound(updateErr) {
			writeError(w, http.StatusNotFound, "not_found", "VM not found", nil)
			return
		}
		if isConflictError(updateErr) {
			writeError(w, http.StatusConflict, "conflict", "subdomain already exists", nil)
			return
		}
		if req.ExposeSubdomain && updateErr.Error() == "vm must be running to expose" {
			writeError(w, http.StatusConflict, "conflict", "vm must be running to expose", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to update VM exposure", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func vmToResponse(vm *db.VM, userHandle string, exposure fireslice.VMExposure) vmResponse {
	return vmResponse{
		ID:              vm.ID,
		UserID:          vm.UserID,
		UserHandle:      userHandle,
		Name:            vm.Name,
		Status:          vm.Status,
		Image:           vm.Image,
		VCPU:            vm.VCPU,
		MemoryMB:        vm.MemoryMB,
		DiskGB:          vm.DiskGB,
		IPAddress:       stringPtrFromNull(vm.IPAddress),
		TapDevice:       stringPtrFromNull(vm.TapDevice),
		MACAddress:      stringPtrFromNull(vm.MACAddress),
		PID:             int64PtrFromNull(vm.PID),
		ExposeSubdomain: exposure.ExposeSubdomain,
		Subdomain:       exposure.Subdomain,
		ExposedPort:     exposure.ExposedPort,
		CreatedAt:       formatTime(vm.CreatedAt),
		UpdatedAt:       formatTime(vm.UpdatedAt),
	}
}
