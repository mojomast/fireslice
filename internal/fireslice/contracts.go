package fireslice

import (
	"context"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/vm"
)

// CreateVMInput is the shared contract between the admin API, service layer,
// and DB helpers for creating a managed VM.
type CreateVMInput struct {
	UserID          int64
	Name            string
	Image           string
	VCPU            int
	MemoryMB        int
	DiskGB          int
	ExposeSubdomain bool
	Subdomain       string
	ExposedPort     int
}

type VMExposure struct {
	ExposeSubdomain bool
	Subdomain       string
	ExposedPort     int
}

type UserStore interface {
	CreateUser(ctx context.Context, handle, email string) (*db.User, error)
	GetUser(ctx context.Context, id int64) (*db.User, error)
	ListUsers(ctx context.Context) ([]*db.User, error)
	DeleteUser(ctx context.Context, id int64) error
	AddSSHKey(ctx context.Context, userID int64, publicKey, label string) (*db.SSHKey, error)
	DeleteSSHKey(ctx context.Context, userID, keyID int64) error
	ListSSHKeys(ctx context.Context, userID int64) ([]*db.SSHKey, error)
}

type VMStore interface {
	CreateVMRecord(ctx context.Context, input CreateVMInput) (*db.VM, error)
	GetVM(ctx context.Context, id int64) (*db.VM, error)
	ListVMs(ctx context.Context) ([]*db.VM, error)
	UpdateVMStatus(ctx context.Context, id int64, status string) error
	UpdateVMExposure(ctx context.Context, id int64, expose bool, subdomain string, port int) error
	DeleteVM(ctx context.Context, id int64) error
}

type VMRuntime interface {
	CreateAndStartWithOptions(ctx context.Context, opts vm.CreateOptions) error
	Start(ctx context.Context, vmID int64) error
	Stop(ctx context.Context, vmID int64) error
	Destroy(ctx context.Context, vmID int64) error
}

type RouteManager interface {
	AddRoute(ctx context.Context, vmName, vmIP string, port int) error
	RemoveRoute(ctx context.Context, vmName string) error
}

type AuditStore interface {
	LogAudit(ctx context.Context, action, targetType string, targetID int64, detail string) error
}
