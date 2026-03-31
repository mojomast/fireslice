package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/fireslice"
	"github.com/mojomast/fireslice/internal/vm"
)

const testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILi2Zf8Bq4J0oQ4Sx7z3qY8pM2w0N1vGv4uO0v9C7A2X test@example"

func TestHealthEndpointUsesAuthMiddleware(t *testing.T) {
	called := false
	h := New(&fireslice.Service{}, Options{
		AuthMiddleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), Principal{Subject: "admin", Role: "admin"})))
			})
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, basePath+"/health", nil)
	h.HTTPHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("expected auth middleware to be invoked")
	}
	principal, ok := PrincipalFromContext(req.Context())
	if ok || principal.Subject != "" {
		t.Fatal("middleware should not mutate original request context")
	}
}

func TestUserEndpoints(t *testing.T) {
	now := mustTime("2026-03-30T12:00:00Z")
	users := &stubUsers{
		listUsers: []*db.User{
			{ID: 2, Handle: "zoe", Email: "zoe@example.com", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
			{ID: 1, Handle: "alice", Email: "alice@example.com", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
		},
		getUser: map[int64]*db.User{
			1: {ID: 1, Handle: "alice", Email: "alice@example.com", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
		},
		keysByUser: map[int64][]*db.SSHKey{
			1: {{ID: 11, UserID: 1, PublicKey: testPublicKey, Fingerprint: "SHA256:abc", Comment: "macbook", CreatedAt: db.SQLiteTime{Time: now}}},
			2: {},
		},
		createUserResult: &db.User{ID: 3, Handle: "bob", Email: "bob@example.com", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
		addKeyResult:     &db.SSHKey{ID: 12, UserID: 3, PublicKey: testPublicKey, Fingerprint: "SHA256:def", Comment: "laptop", CreatedAt: db.SQLiteTime{Time: now}},
		deleteUserIDs:    map[int64]bool{},
		deleteKeyIDs:     map[int64]bool{},
	}
	vms := &stubVMs{
		listVMs: []*db.VM{{ID: 21, UserID: 1, Name: "alice-box", Status: "running", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}},
	}
	audit := &stubAudit{}
	h := newAuthedHandler(&fireslice.Service{Users: users, VMs: vms}, audit, Principal{Subject: "admin", UserID: 99, Role: "admin"})
	srv := h.HTTPHandler()

	t.Run("list users", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/users", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)
		items := body["users"].([]any)
		if len(items) != 2 {
			t.Fatalf("user count = %d, want 2", len(items))
		}
		first := items[0].(map[string]any)
		if first["handle"] != "alice" {
			t.Fatalf("first handle = %v, want alice", first["handle"])
		}
		if first["vm_count"].(float64) != 1 {
			t.Fatalf("vm_count = %v, want 1", first["vm_count"])
		}
	})

	t.Run("create user with first key", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/users", map[string]any{
			"handle": "bob",
			"email":  "bob@example.com",
			"first_key": map[string]any{
				"public_key": testPublicKey,
				"label":      "laptop",
			},
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusCreated)
		if users.createUserCalls != 1 {
			t.Fatalf("create user calls = %d, want 1", users.createUserCalls)
		}
		if users.addKeyCalls != 1 {
			t.Fatalf("add key calls = %d, want 1", users.addKeyCalls)
		}
		if len(audit.events) != 2 {
			t.Fatalf("audit events = %d, want 2", len(audit.events))
		}
	})

	t.Run("create user validation failure", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/users", map[string]any{
			"handle": "Bad Handle",
			"first_key": map[string]any{
				"public_key": "not-a-key",
				"label":      "",
			},
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusUnprocessableEntity)
		body := decodeBody(t, rec)
		errObj := body["error"].(map[string]any)
		details := errObj["details"].(map[string]any)
		if _, ok := details["handle"]; !ok {
			t.Fatal("expected handle validation error")
		}
		if _, ok := details["first_key.public_key"]; !ok {
			t.Fatal("expected public key validation error")
		}
	})

	t.Run("get user detail", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/users/1", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)
		user := body["user"].(map[string]any)
		if user["handle"] != "alice" {
			t.Fatalf("handle = %v, want alice", user["handle"])
		}
		if user["vm_count"].(float64) != 1 {
			t.Fatalf("vm_count = %v, want 1", user["vm_count"])
		}
	})

	t.Run("get user not found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/users/99", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNotFound)
	})

	t.Run("add user key", func(t *testing.T) {
		users.addKeyResult = &db.SSHKey{ID: 13, UserID: 1, PublicKey: testPublicKey, Fingerprint: "SHA256:ghi", Comment: "desktop", CreatedAt: db.SQLiteTime{Time: now}}
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/users/1/keys", map[string]any{
			"public_key": testPublicKey,
			"label":      "desktop",
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusCreated)
	})

	t.Run("delete user key", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, basePath+"/users/1/keys/11", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNoContent)
		if !users.deleteKeyIDs[11] {
			t.Fatal("expected key deletion to be recorded")
		}
	})

	t.Run("update user password", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/users/1/password", map[string]any{"password": "new-secret"})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNoContent)
	})

	t.Run("update user quotas", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPatch, basePath+"/users/1/quotas", map[string]any{"trust_level": "citizen", "vm_limit": 10, "cpu_limit": 4, "ram_limit_mb": 8192, "disk_limit_mb": 51200})
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusNoContent)
		if users.updatedQuotaUserID != 1 || users.updatedTrustLevel != "citizen" {
			t.Fatalf("quota update target = %d/%q", users.updatedQuotaUserID, users.updatedTrustLevel)
		}
	})

	t.Run("delete user", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, basePath+"/users/1", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNoContent)
		if !users.deleteUserIDs[1] {
			t.Fatal("expected user deletion to be recorded")
		}
	})

	t.Run("delete user invalid path", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, basePath+"/users/bad", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusBadRequest)
	})

	t.Run("create user conflict", func(t *testing.T) {
		users.createUserErr = errors.New("UNIQUE constraint failed: users.handle")
		defer func() { users.createUserErr = nil }()

		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/users", map[string]any{"handle": "alice"})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusConflict)
	})
}

func TestVMEndpoints(t *testing.T) {
	now := mustTime("2026-03-30T12:00:00Z")
	users := &stubUsers{
		getUser:    map[int64]*db.User{1: {ID: 1, Handle: "alice", Email: "alice@example.com", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}},
		keysByUser: map[int64][]*db.SSHKey{1: {{ID: 11, UserID: 1, PublicKey: testPublicKey, Fingerprint: "SHA256:abc", Comment: "macbook", CreatedAt: db.SQLiteTime{Time: now}}}},
	}
	vms := &stubVMs{
		listVMs:        []*db.VM{{ID: 21, UserID: 1, Name: "zeta", Status: "stopped", Image: "ussyuntu", VCPU: 1, MemoryMB: 512, DiskGB: 10, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}, {ID: 20, UserID: 1, Name: "alpha", Status: "running", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}},
		getVM:          map[int64]*db.VM{20: {ID: 20, UserID: 1, Name: "alpha", Status: "running", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}},
		createVMResult: &db.VM{ID: 22, UserID: 1, Name: "newbox", Status: "creating", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
		exposure:       map[int64]fireslice.VMExposure{20: {ExposeSubdomain: true, Subdomain: "alpha", ExposedPort: 8080}, 21: {ExposeSubdomain: false, ExposedPort: 8080}},
	}
	runtime := &stubVMRuntime{}
	audit := &stubAudit{}
	h := newAuthedHandler(&fireslice.Service{Users: users, VMs: vms, VMRun: runtime}, audit, Principal{Subject: "admin", UserID: 99, Role: "admin"})
	srv := h.HTTPHandler()

	t.Run("list vms", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/vms", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)
		items := body["vms"].([]any)
		first := items[0].(map[string]any)
		if first["name"] != "alpha" {
			t.Fatalf("first name = %v, want alpha", first["name"])
		}
		if first["user_handle"] != "alice" {
			t.Fatalf("user_handle = %v, want alice", first["user_handle"])
		}
	})

	t.Run("create vm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/vms", map[string]any{
			"user_id":          1,
			"name":             "newbox",
			"image":            "ussyuntu",
			"vcpu":             2,
			"memory_mb":        1024,
			"disk_gb":          20,
			"expose_subdomain": true,
			"subdomain":        "newbox",
			"exposed_port":     8080,
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusCreated)
		if rec.Code != http.StatusCreated {
			t.Fatalf("body: %s", rec.Body.String())
		}
		if vms.createVMInput.Name != "newbox" {
			t.Fatalf("created vm name = %q, want newbox", vms.createVMInput.Name)
		}
		if runtime.createCalls != 1 {
			t.Fatalf("runtime create calls = %d, want 1", runtime.createCalls)
		}
	})

	t.Run("create vm invalid exposure", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/vms", map[string]any{
			"user_id":          1,
			"name":             "newbox",
			"image":            "ussyuntu",
			"vcpu":             2,
			"memory_mb":        1024,
			"disk_gb":          20,
			"expose_subdomain": true,
			"subdomain":        "",
			"exposed_port":     70000,
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusUnprocessableEntity)
	})

	t.Run("create vm quota exceeded", func(t *testing.T) {
		users.getUser[1].VMLimit = 1
		vms.listVMs = []*db.VM{{ID: 20, UserID: 1, Name: "alpha", Status: "running", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}}
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/vms", map[string]any{"user_id": 1, "name": "extra", "image": "ussyuntu", "vcpu": 1, "memory_mb": 512, "disk_gb": 10, "expose_subdomain": false})
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusConflict)
		users.getUser[1].VMLimit = 0
		vms.listVMs = []*db.VM{{ID: 21, UserID: 1, Name: "zeta", Status: "stopped", Image: "ussyuntu", VCPU: 1, MemoryMB: 512, DiskGB: 10, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}, {ID: 20, UserID: 1, Name: "alpha", Status: "running", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}}
	})

	t.Run("create vm conflict", func(t *testing.T) {
		vms.createVMErr = errors.New("duplicate vm")
		defer func() { vms.createVMErr = nil }()

		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/vms", map[string]any{
			"user_id":          1,
			"name":             "alpha",
			"image":            "ussyuntu",
			"vcpu":             2,
			"memory_mb":        1024,
			"disk_gb":          20,
			"expose_subdomain": false,
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusConflict)
	})

	t.Run("get vm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/vms/20", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)
		vm := body["vm"].(map[string]any)
		if vm["subdomain"] != "alpha" {
			t.Fatalf("subdomain = %v, want alpha", vm["subdomain"])
		}
	})

	t.Run("start vm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, basePath+"/vms/20/start", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNoContent)
		if runtime.startIDs[0] != 20 {
			t.Fatalf("start id = %d, want 20", runtime.startIDs[0])
		}
		if vms.statusUpdates[20] != "running" {
			t.Fatalf("status update = %q, want running", vms.statusUpdates[20])
		}
	})

	t.Run("stop vm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, basePath+"/vms/20/stop", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNoContent)
		if runtime.stopIDs[0] != 20 {
			t.Fatalf("stop id = %d, want 20", runtime.stopIDs[0])
		}
		if vms.statusUpdates[20] != "stopped" {
			t.Fatalf("status update = %q, want stopped", vms.statusUpdates[20])
		}
	})

	t.Run("patch exposure", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPatch, basePath+"/vms/20/exposure", map[string]any{
			"expose_subdomain": true,
			"subdomain":        "alpha",
			"exposed_port":     8080,
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNoContent)
		if !vms.updateExposureCalled {
			t.Fatal("expected exposure update")
		}
	})

	t.Run("patch exposure invalid port", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPatch, basePath+"/vms/20/exposure", map[string]any{
			"expose_subdomain": true,
			"subdomain":        "alpha",
			"exposed_port":     0,
		})
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusUnprocessableEntity)
	})

	t.Run("delete vm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, basePath+"/vms/20", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNoContent)
		if runtime.destroyIDs[0] != 20 {
			t.Fatalf("destroy id = %d, want 20", runtime.destroyIDs[0])
		}
		if !vms.deleted[20] {
			t.Fatal("expected vm deletion")
		}
	})

	t.Run("vm not found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/vms/99", nil)
		srv.ServeHTTP(rec, req)

		assertStatus(t, rec, http.StatusNotFound)
	})
}

func TestUserScopedAuthorization(t *testing.T) {
	now := mustTime("2026-03-30T12:00:00Z")
	users := &stubUsers{
		listUsers: []*db.User{{ID: 1, Handle: "alice", Email: "alice@example.com", Role: "user", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}, {ID: 2, Handle: "bob", Email: "bob@example.com", Role: "user", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}}},
		getUser: map[int64]*db.User{
			1: {ID: 1, Handle: "alice", Email: "alice@example.com", Role: "user", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
			2: {ID: 2, Handle: "bob", Email: "bob@example.com", Role: "user", TrustLevel: "citizen", VMLimit: 10, CPULimit: 8, RAMLimitMB: 8192, DiskLimitMB: 51200, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
		},
		keysByUser:    map[int64][]*db.SSHKey{1: {}, 2: {}},
		deleteKeyIDs:  map[int64]bool{},
		deleteUserIDs: map[int64]bool{},
	}
	vms := &stubVMs{
		listVMs: []*db.VM{
			{ID: 20, UserID: 1, Name: "alice-box", Status: "running", Image: "ussyuntu", VCPU: 1, MemoryMB: 512, DiskGB: 10, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
			{ID: 21, UserID: 2, Name: "bob-box", Status: "running", Image: "ussyuntu", VCPU: 1, MemoryMB: 512, DiskGB: 10, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
		},
		getVM: map[int64]*db.VM{
			20: {ID: 20, UserID: 1, Name: "alice-box", Status: "running", Image: "ussyuntu", VCPU: 1, MemoryMB: 512, DiskGB: 10, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
			21: {ID: 21, UserID: 2, Name: "bob-box", Status: "running", Image: "ussyuntu", VCPU: 1, MemoryMB: 512, DiskGB: 10, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
		},
		createVMResult: &db.VM{ID: 22, UserID: 2, Name: "newbox", Status: "creating", Image: "ussyuntu", VCPU: 1, MemoryMB: 512, DiskGB: 10, CreatedAt: db.SQLiteTime{Time: now}, UpdatedAt: db.SQLiteTime{Time: now}},
	}
	runtime := &stubVMRuntime{}
	audit := &stubAudit{}
	h := newAuthedHandler(&fireslice.Service{Users: users, VMs: vms, VMRun: runtime}, audit, Principal{Subject: "bob", UserID: 2, Role: "user"})
	srv := h.HTTPHandler()

	t.Run("cannot list all users", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/users", nil)
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusForbidden)
	})

	t.Run("can read self user", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/users/2", nil)
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusOK)
	})

	t.Run("cannot read another user", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/users/1", nil)
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusForbidden)
	})

	t.Run("can update own password", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/users/2/password", map[string]any{"password": "changed"})
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusNoContent)
	})

	t.Run("cannot update another password", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/users/1/password", map[string]any{"password": "changed"})
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusForbidden)
	})

	t.Run("lists only own vms", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/vms", nil)
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)
		items := body["vms"].([]any)
		if len(items) != 1 {
			t.Fatalf("vm count = %d, want 1", len(items))
		}
		first := items[0].(map[string]any)
		if first["user_id"].(float64) != 2 {
			t.Fatalf("user_id = %v, want 2", first["user_id"])
		}
	})

	t.Run("forces create vm to current user", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, basePath+"/vms", map[string]any{
			"user_id":          1,
			"name":             "newbox",
			"image":            "ussyuntu",
			"vcpu":             1,
			"memory_mb":        512,
			"disk_gb":          10,
			"expose_subdomain": false,
		})
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusCreated)
		if vms.createVMInput.UserID != 2 {
			t.Fatalf("created vm user id = %d, want 2", vms.createVMInput.UserID)
		}
	})

	t.Run("cannot access another vm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/vms/20", nil)
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusForbidden)
	})

	t.Run("can access own vm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, basePath+"/vms/21", nil)
		srv.ServeHTTP(rec, req)
		assertStatus(t, rec, http.StatusOK)
	})
}

type stubUsers struct {
	listUsers          []*db.User
	getUser            map[int64]*db.User
	keysByUser         map[int64][]*db.SSHKey
	createUserResult   *db.User
	createUserErr      error
	addKeyResult       *db.SSHKey
	addKeyErr          error
	createUserCalls    int
	addKeyCalls        int
	deleteUserIDs      map[int64]bool
	deleteKeyIDs       map[int64]bool
	updatedQuotaUserID int64
	updatedTrustLevel  string
}

func (s *stubUsers) CreateUser(_ context.Context, handle, email, _ string, role string) (*db.User, error) {
	s.createUserCalls++
	if s.createUserErr != nil {
		return nil, s.createUserErr
	}
	user := *s.createUserResult
	user.Handle = handle
	user.Email = email
	if role != "" {
		user.Role = role
	}
	return &user, nil
}

func (s *stubUsers) GetUser(_ context.Context, id int64) (*db.User, error) {
	user, ok := s.getUser[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	copy := *user
	return &copy, nil
}

func (s *stubUsers) GetUserByHandle(_ context.Context, handle string) (*db.User, error) {
	for _, user := range s.getUser {
		if user.Handle == handle {
			copy := *user
			return &copy, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (s *stubUsers) ListUsers(_ context.Context) ([]*db.User, error) {
	items := make([]*db.User, 0, len(s.listUsers))
	for _, user := range s.listUsers {
		copy := *user
		items = append(items, &copy)
	}
	return items, nil
}

func (s *stubUsers) DeleteUser(_ context.Context, id int64) error {
	if _, ok := s.getUser[id]; !ok {
		return sql.ErrNoRows
	}
	s.deleteUserIDs[id] = true
	return nil
}

func (s *stubUsers) UpdatePassword(_ context.Context, id int64, _ string) error {
	if _, ok := s.getUser[id]; !ok {
		return sql.ErrNoRows
	}
	return nil
}

func (s *stubUsers) UpdateQuotas(_ context.Context, userID int64, trustLevel string, vmLimit, cpuLimit, ramLimitMB, diskLimitMB int) error {
	if _, ok := s.getUser[userID]; !ok {
		return sql.ErrNoRows
	}
	s.updatedQuotaUserID = userID
	s.updatedTrustLevel = trustLevel
	user := s.getUser[userID]
	user.TrustLevel = trustLevel
	user.VMLimit = vmLimit
	user.CPULimit = cpuLimit
	user.RAMLimitMB = ramLimitMB
	user.DiskLimitMB = diskLimitMB
	return nil
}

func (s *stubUsers) AddSSHKey(_ context.Context, userID int64, publicKey, label string) (*db.SSHKey, error) {
	s.addKeyCalls++
	if s.addKeyErr != nil {
		return nil, s.addKeyErr
	}
	if _, ok := s.getUser[userID]; len(s.getUser) > 0 && !ok && userID != s.addKeyResult.UserID {
		return nil, sql.ErrNoRows
	}
	key := *s.addKeyResult
	key.UserID = userID
	key.PublicKey = publicKey
	key.Comment = label
	return &key, nil
}

func (s *stubUsers) DeleteSSHKey(_ context.Context, _ int64, keyID int64) error {
	s.deleteKeyIDs[keyID] = true
	return nil
}

func (s *stubUsers) ListSSHKeys(_ context.Context, userID int64) ([]*db.SSHKey, error) {
	items := s.keysByUser[userID]
	result := make([]*db.SSHKey, 0, len(items))
	for _, key := range items {
		copy := *key
		result = append(result, &copy)
	}
	return result, nil
}

type stubVMs struct {
	listVMs              []*db.VM
	getVM                map[int64]*db.VM
	createVMResult       *db.VM
	createVMErr          error
	createVMInput        fireslice.CreateVMInput
	statusUpdates        map[int64]string
	deleted              map[int64]bool
	updateExposureCalled bool
	exposure             map[int64]fireslice.VMExposure
}

func (s *stubVMs) CreateVMRecord(_ context.Context, input fireslice.CreateVMInput) (*db.VM, error) {
	s.createVMInput = input
	if s.createVMErr != nil {
		return nil, s.createVMErr
	}
	copy := *s.createVMResult
	copy.Status = "running"
	copy.ExposeSubdomain = input.ExposeSubdomain
	if input.Subdomain != "" {
		copy.Subdomain = sql.NullString{String: input.Subdomain, Valid: true}
	}
	copy.ExposedPort = input.ExposedPort
	if s.getVM == nil {
		s.getVM = map[int64]*db.VM{}
	}
	stored := copy
	s.getVM[copy.ID] = &stored
	return &copy, nil
}

func (s *stubVMs) GetVM(_ context.Context, id int64) (*db.VM, error) {
	vm, ok := s.getVM[id]
	if !ok {
		return nil, sql.ErrNoRows
	}
	copy := *vm
	return &copy, nil
}

func (s *stubVMs) ListVMs(_ context.Context) ([]*db.VM, error) {
	items := make([]*db.VM, 0, len(s.listVMs))
	for _, vm := range s.listVMs {
		copy := *vm
		items = append(items, &copy)
	}
	return items, nil
}

func (s *stubVMs) ListVMsByUser(_ context.Context, userID int64) ([]*db.VM, error) {
	items := make([]*db.VM, 0)
	for _, vm := range s.listVMs {
		if vm.UserID != userID {
			continue
		}
		copy := *vm
		items = append(items, &copy)
	}
	return items, nil
}

func (s *stubVMs) UpdateVMStatus(_ context.Context, id int64, status string) error {
	if s.statusUpdates == nil {
		s.statusUpdates = map[int64]string{}
	}
	s.statusUpdates[id] = status
	return nil
}

func (s *stubVMs) UpdateVMExposure(_ context.Context, id int64, expose bool, subdomain string, port int) error {
	s.updateExposureCalled = true
	if s.exposure == nil {
		s.exposure = map[int64]fireslice.VMExposure{}
	}
	s.exposure[id] = fireslice.VMExposure{ExposeSubdomain: expose, Subdomain: subdomain, ExposedPort: port}
	return nil
}

func (s *stubVMs) DeleteVM(_ context.Context, id int64) error {
	if s.deleted == nil {
		s.deleted = map[int64]bool{}
	}
	s.deleted[id] = true
	return nil
}

func (s *stubVMs) GetVMExposure(_ context.Context, id int64) (fireslice.VMExposure, error) {
	return s.exposure[id], nil
}

type stubVMRuntime struct {
	createCalls int
	startIDs    []int64
	stopIDs     []int64
	destroyIDs  []int64
}

func (s *stubVMRuntime) CreateAndStartWithOptions(_ context.Context, _ vm.CreateOptions) error {
	s.createCalls++
	return nil
}

func (s *stubVMRuntime) Start(_ context.Context, id int64) error {
	s.startIDs = append(s.startIDs, id)
	return nil
}

func (s *stubVMRuntime) Stop(_ context.Context, id int64) error {
	s.stopIDs = append(s.stopIDs, id)
	return nil
}

func (s *stubVMRuntime) Destroy(_ context.Context, id int64) error {
	s.destroyIDs = append(s.destroyIDs, id)
	return nil
}

type stubAudit struct {
	events []string
}

func (s *stubAudit) LogAudit(_ context.Context, action, targetType string, targetID int64, detail string) error {
	s.events = append(s.events, strings.Join([]string{action, targetType, detail}, ":"))
	return nil
}

func jsonRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v\nbody=%s", err, rec.Body.String())
	}
	return body
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, want, rec.Body.String())
	}
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func newAuthedHandler(service *fireslice.Service, audit AuditLogger, principal Principal) *Handler {
	return New(service, Options{
		AuditLogger: audit,
		AuthMiddleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
			})
		},
	})
}
