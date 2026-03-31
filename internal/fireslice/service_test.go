package fireslice

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/vm"
)

func TestServiceCreateVM(t *testing.T) {
	now := db.SQLiteTime{Time: time.Now()}
	users := &serviceStubUsers{
		get:  map[int64]*db.User{1: {ID: 1, Handle: "alice", VMLimit: 3, CPULimit: 4, RAMLimitMB: 4096, DiskLimitMB: 40960}},
		keys: map[int64][]*db.SSHKey{1: {{ID: 1, UserID: 1, PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILi2Zf8Bq4J0oQ4Sx7z3qY8pM2w0N1vGv4uO0v9C7A2X test@example", Fingerprint: "SHA256:x", CreatedAt: now}}},
	}
	vms := &serviceStubVMs{
		created: &db.VM{ID: 10, UserID: 1, Name: "alpha", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, Status: "creating", CreatedAt: now, UpdatedAt: now},
		get:     map[int64]*db.VM{},
		byUser:  map[int64][]*db.VM{},
	}
	runtime := &serviceStubRuntime{}
	service := &Service{Users: users, VMs: vms, VMRun: runtime}

	vmRecord, err := service.CreateVM(context.Background(), CreateVMInput{UserID: 1, Name: "alpha", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20})
	if err != nil {
		t.Fatal(err)
	}
	if vmRecord.ID != 10 {
		t.Fatalf("vm id = %d, want 10", vmRecord.ID)
	}
	if runtime.calls != 1 {
		t.Fatalf("runtime calls = %d, want 1", runtime.calls)
	}
}

func TestServiceCreateVMQuotaEnforced(t *testing.T) {
	now := db.SQLiteTime{Time: time.Now()}
	users := &serviceStubUsers{get: map[int64]*db.User{1: {ID: 1, Handle: "alice", VMLimit: 1, CPULimit: 2, RAMLimitMB: 2048, DiskLimitMB: 20480}}}
	vms := &serviceStubVMs{
		created: &db.VM{ID: 10, UserID: 1, Name: "beta", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20, Status: "creating", CreatedAt: now, UpdatedAt: now},
		get:     map[int64]*db.VM{},
		byUser: map[int64][]*db.VM{1: {
			{ID: 9, UserID: 1, Name: "alpha", VCPU: 1, MemoryMB: 1024, DiskGB: 10, Status: "running", CreatedAt: now, UpdatedAt: now},
		}},
	}
	service := &Service{Users: users, VMs: vms, VMRun: &serviceStubRuntime{}}

	if _, err := service.CreateVM(context.Background(), CreateVMInput{UserID: 1, Name: "beta", Image: "ussyuntu", VCPU: 2, MemoryMB: 1024, DiskGB: 20}); err == nil || err.Error() != "vm quota exceeded" {
		t.Fatalf("expected vm quota exceeded, got %v", err)
	}
}

func TestServiceUpdateUserQuotas(t *testing.T) {
	users := &serviceStubUsers{get: map[int64]*db.User{1: {ID: 1, Handle: "alice"}}}
	service := &Service{Users: users}

	if err := service.UpdateUserQuotas(context.Background(), 1, "citizen", 10, 4, 8192, 51200); err != nil {
		t.Fatal(err)
	}
	if users.updatedQuotaUserID != 1 || users.updatedTrustLevel != "citizen" {
		t.Fatalf("quota update target = %d/%q", users.updatedQuotaUserID, users.updatedTrustLevel)
	}
}

func TestServiceCreateVMRejectsUnknownImage(t *testing.T) {
	users := &serviceStubUsers{get: map[int64]*db.User{1: {ID: 1, Handle: "alice", VMLimit: 3, CPULimit: 4, RAMLimitMB: 4096, DiskLimitMB: 40960}}}
	vms := &serviceStubVMs{created: &db.VM{ID: 10, UserID: 1, Name: "alpha", Image: "custom", VCPU: 2, MemoryMB: 1024, DiskGB: 20}, get: map[int64]*db.VM{}, byUser: map[int64][]*db.VM{}}
	service := &Service{Users: users, VMs: vms, VMRun: &serviceStubRuntime{}, Images: stubImageStore{images: []ImageCatalogEntry{{Name: "ussyuntu", Ref: "ussyuntu"}}}}

	if _, err := service.CreateVM(context.Background(), CreateVMInput{UserID: 1, Name: "alpha", Image: "custom", VCPU: 2, MemoryMB: 1024, DiskGB: 20}); err == nil || err.Error() != "image is not available" {
		t.Fatalf("expected image rejection, got %v", err)
	}
}

type serviceStubUsers struct {
	get                map[int64]*db.User
	keys               map[int64][]*db.SSHKey
	updatedQuotaUserID int64
	updatedTrustLevel  string
}

func (s *serviceStubUsers) CreateUser(context.Context, string, string, string, string) (*db.User, error) {
	return nil, nil
}
func (s *serviceStubUsers) GetUser(_ context.Context, id int64) (*db.User, error) {
	if user, ok := s.get[id]; ok {
		copy := *user
		return &copy, nil
	}
	return nil, sql.ErrNoRows
}
func (s *serviceStubUsers) GetUserByHandle(context.Context, string) (*db.User, error) {
	return nil, nil
}
func (s *serviceStubUsers) ListUsers(context.Context) ([]*db.User, error)       { return nil, nil }
func (s *serviceStubUsers) DeleteUser(context.Context, int64) error             { return nil }
func (s *serviceStubUsers) UpdatePassword(context.Context, int64, string) error { return nil }
func (s *serviceStubUsers) UpdateQuotas(_ context.Context, userID int64, trustLevel string, vmLimit, cpuLimit, ramLimitMB, diskLimitMB int) error {
	s.updatedQuotaUserID = userID
	s.updatedTrustLevel = trustLevel
	if user, ok := s.get[userID]; ok {
		user.TrustLevel = trustLevel
		user.VMLimit = vmLimit
		user.CPULimit = cpuLimit
		user.RAMLimitMB = ramLimitMB
		user.DiskLimitMB = diskLimitMB
		return nil
	}
	return sql.ErrNoRows
}
func (s *serviceStubUsers) AddSSHKey(context.Context, int64, string, string) (*db.SSHKey, error) {
	return nil, nil
}
func (s *serviceStubUsers) DeleteSSHKey(context.Context, int64, int64) error { return nil }
func (s *serviceStubUsers) ListSSHKeys(_ context.Context, userID int64) ([]*db.SSHKey, error) {
	return s.keys[userID], nil
}

type serviceStubVMs struct {
	created *db.VM
	get     map[int64]*db.VM
	byUser  map[int64][]*db.VM
}

func (s *serviceStubVMs) CreateVMRecord(_ context.Context, input CreateVMInput) (*db.VM, error) {
	copy := *s.created
	copy.ExposeSubdomain = input.ExposeSubdomain
	copy.ExposedPort = input.ExposedPort
	if input.Subdomain != "" {
		copy.Subdomain = sql.NullString{String: input.Subdomain, Valid: true}
	}
	copy.Status = "running"
	s.get[copy.ID] = &copy
	return &copy, nil
}
func (s *serviceStubVMs) GetVM(_ context.Context, id int64) (*db.VM, error) { return s.get[id], nil }
func (s *serviceStubVMs) ListVMs(context.Context) ([]*db.VM, error)         { return nil, nil }
func (s *serviceStubVMs) ListVMsByUser(_ context.Context, userID int64) ([]*db.VM, error) {
	items := s.byUser[userID]
	out := make([]*db.VM, 0, len(items))
	for _, vm := range items {
		copy := *vm
		out = append(out, &copy)
	}
	return out, nil
}
func (s *serviceStubVMs) UpdateVMStatus(context.Context, int64, string) error { return nil }
func (s *serviceStubVMs) UpdateVMExposure(context.Context, int64, bool, string, int) error {
	return nil
}
func (s *serviceStubVMs) DeleteVM(context.Context, int64) error { return nil }

type serviceStubRuntime struct{ calls int }

type stubImageStore struct{ images []ImageCatalogEntry }

func (s stubImageStore) ListImages(context.Context) ([]ImageCatalogEntry, error) {
	return s.images, nil
}
func (s stubImageStore) AddImage(context.Context, ImageCatalogEntry) error { return nil }
func (s stubImageStore) DeleteImage(context.Context, string) error         { return nil }

func (s *serviceStubRuntime) CreateAndStartWithOptions(context.Context, vm.CreateOptions) error {
	s.calls++
	return nil
}
func (s *serviceStubRuntime) Start(context.Context, int64) error   { return nil }
func (s *serviceStubRuntime) Stop(context.Context, int64) error    { return nil }
func (s *serviceStubRuntime) Destroy(context.Context, int64) error { return nil }
