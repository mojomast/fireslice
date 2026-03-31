package fireslice

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/vm"
)

type Service struct {
	Users  UserStore
	VMs    VMStore
	VMRun  VMRuntime
	Routes RouteManager
	Audit  AuditStore
}

func NewService(users UserStore, vms VMStore, vmRun VMRuntime, routes RouteManager) *Service {
	return &Service{
		Users:  users,
		VMs:    vms,
		VMRun:  vmRun,
		Routes: routes,
	}
}

func (s *Service) CreateVM(ctx context.Context, input CreateVMInput) (*db.VM, error) {
	if s.VMs == nil {
		return nil, fmt.Errorf("vm store unavailable")
	}
	vmRecord, err := s.VMs.CreateVMRecord(ctx, input)
	if err != nil {
		return nil, err
	}

	if s.VMRun != nil {
		keys, err := s.userKeys(ctx, input.UserID)
		if err != nil {
			return nil, err
		}
		if err := s.VMRun.CreateAndStartWithOptions(ctx, vm.CreateOptions{
			VMID:       vmRecord.ID,
			Name:       vmRecord.Name,
			ImageRef:   vmRecord.Image,
			VCPU:       vmRecord.VCPU,
			MemoryMB:   vmRecord.MemoryMB,
			DataDiskGB: vmRecord.DiskGB,
			SSHKeys:    keys,
			Env:        map[string]string{},
		}); err != nil {
			return nil, err
		}
		vmRecord.Status = "running"
	}

	if input.ExposeSubdomain {
		if err := s.ExposeVM(ctx, vmRecord.ID, input.Subdomain, input.ExposedPort); err != nil {
			return nil, err
		}
	}

	_ = s.logAudit(ctx, "vm.created", "vm", vmRecord.ID, vmRecord.Name)
	return s.VMs.GetVM(ctx, vmRecord.ID)
}

func (s *Service) StartVM(ctx context.Context, id int64) error {
	if s.VMs == nil || s.VMRun == nil {
		return fmt.Errorf("vm runtime unavailable")
	}
	vmRecord, err := s.VMs.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if err := s.VMRun.Start(ctx, id); err != nil {
		return err
	}
	if err := s.VMs.UpdateVMStatus(ctx, id, "running"); err != nil {
		return err
	}
	if vmRecord.ExposeSubdomain {
		if err := s.addRoute(ctx, vmRecord); err != nil {
			return err
		}
	}
	return s.logAudit(ctx, "vm.started", "vm", id, "")
}

func (s *Service) StopVM(ctx context.Context, id int64) error {
	if s.VMs == nil || s.VMRun == nil {
		return fmt.Errorf("vm runtime unavailable")
	}
	vmRecord, err := s.VMs.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vmRecord.ExposeSubdomain {
		_ = s.removeRoute(ctx, vmRecord)
	}
	if err := s.VMRun.Stop(ctx, id); err != nil {
		return err
	}
	if err := s.VMs.UpdateVMStatus(ctx, id, "stopped"); err != nil {
		return err
	}
	return s.logAudit(ctx, "vm.stopped", "vm", id, "")
}

func (s *Service) DestroyVM(ctx context.Context, id int64) error {
	if s.VMs == nil || s.VMRun == nil {
		return fmt.Errorf("vm runtime unavailable")
	}
	vmRecord, err := s.VMs.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vmRecord.ExposeSubdomain {
		_ = s.removeRoute(ctx, vmRecord)
	}
	if err := s.VMRun.Destroy(ctx, id); err != nil {
		return err
	}
	if err := s.VMs.DeleteVM(ctx, id); err != nil {
		return err
	}
	return s.logAudit(ctx, "vm.destroyed", "vm", id, "")
}

func (s *Service) ExposeVM(ctx context.Context, id int64, subdomain string, port int) error {
	if s.VMs == nil {
		return fmt.Errorf("vm store unavailable")
	}
	vmRecord, err := s.VMs.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vmRecord.Status != "running" {
		return fmt.Errorf("vm must be running to expose")
	}
	if err := s.VMs.UpdateVMExposure(ctx, id, true, subdomain, port); err != nil {
		return err
	}
	vmRecord, err = s.VMs.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if err := s.addRoute(ctx, vmRecord); err != nil {
		return err
	}
	return s.logAudit(ctx, "vm.exposed", "vm", id, vmRecord.Subdomain.String)
}

func (s *Service) HideVM(ctx context.Context, id int64) error {
	if s.VMs == nil {
		return fmt.Errorf("vm store unavailable")
	}
	vmRecord, err := s.VMs.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vmRecord.Subdomain.Valid {
		_ = s.removeRoute(ctx, vmRecord)
	}
	if err := s.VMs.UpdateVMExposure(ctx, id, false, "", vmRecord.ExposedPort); err != nil {
		return err
	}
	return s.logAudit(ctx, "vm.hidden", "vm", id, "")
}

func (s *Service) userKeys(ctx context.Context, userID int64) ([]string, error) {
	if s.Users == nil {
		return nil, nil
	}
	keys, err := s.Users.ListSSHKeys(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key.PublicKey)
	}
	return out, nil
}

func (s *Service) addRoute(ctx context.Context, vmRecord *db.VM) error {
	if s.Routes == nil {
		return nil
	}
	if !vmRecord.Subdomain.Valid {
		return fmt.Errorf("vm subdomain is not configured")
	}
	if !vmRecord.IPAddress.Valid {
		return fmt.Errorf("vm ip address is not available")
	}
	return s.Routes.AddRoute(ctx, vmRecord.Subdomain.String, vmRecord.IPAddress.String, vmRecord.ExposedPort)
}

func (s *Service) removeRoute(ctx context.Context, vmRecord *db.VM) error {
	if s.Routes == nil || !vmRecord.Subdomain.Valid {
		return nil
	}
	return s.Routes.RemoveRoute(ctx, vmRecord.Subdomain.String)
}

func (s *Service) logAudit(ctx context.Context, action, targetType string, targetID int64, detail string) error {
	if s.Audit == nil {
		return nil
	}
	return s.Audit.LogAudit(ctx, action, targetType, targetID, detail)
}

type DirectVMRuntime interface {
	CreateAndStartWithOptions(ctx context.Context, opts vm.CreateOptions) error
	Start(ctx context.Context, vmID int64, name, image string, vcpu, memoryMB int, sshKeys []string) error
	Stop(ctx context.Context, vmID int64) error
	DestroyResources(ctx context.Context, vmID int64) error
}

type VMRuntimeAdapter struct {
	Runtime DirectVMRuntime
	Users   UserStore
	VMs     VMStore
}

func (a *VMRuntimeAdapter) CreateAndStartWithOptions(ctx context.Context, opts vm.CreateOptions) error {
	if a.Runtime == nil {
		return fmt.Errorf("vm runtime unavailable")
	}
	return a.Runtime.CreateAndStartWithOptions(ctx, opts)
}

func (a *VMRuntimeAdapter) Start(ctx context.Context, vmID int64) error {
	if a.Runtime == nil || a.VMs == nil {
		return fmt.Errorf("vm runtime unavailable")
	}
	vmRecord, err := a.VMs.GetVM(ctx, vmID)
	if err != nil {
		return err
	}
	keys, err := a.userKeys(ctx, vmRecord.UserID)
	if err != nil {
		return err
	}
	return a.Runtime.Start(ctx, vmID, vmRecord.Name, vmRecord.Image, vmRecord.VCPU, vmRecord.MemoryMB, keys)
}

func (a *VMRuntimeAdapter) Stop(ctx context.Context, vmID int64) error {
	if a.Runtime == nil {
		return fmt.Errorf("vm runtime unavailable")
	}
	return a.Runtime.Stop(ctx, vmID)
}

func (a *VMRuntimeAdapter) Destroy(ctx context.Context, vmID int64) error {
	if a.Runtime == nil {
		return fmt.Errorf("vm runtime unavailable")
	}
	return a.Runtime.DestroyResources(ctx, vmID)
}

func (a *VMRuntimeAdapter) userKeys(ctx context.Context, userID int64) ([]string, error) {
	if a.Users == nil {
		return nil, nil
	}
	keys, err := a.Users.ListSSHKeys(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key.PublicKey)
	}
	return out, nil
}

type DBUserStore struct{ DB *db.DB }

func (s *DBUserStore) CreateUser(ctx context.Context, handle, email, password, role string) (*db.User, error) {
	return s.DB.CreateFiresliceUser(ctx, handle, email, password, role)
}

func (s *DBUserStore) GetUser(ctx context.Context, id int64) (*db.User, error) {
	return s.DB.GetFiresliceUser(ctx, id)
}

func (s *DBUserStore) GetUserByHandle(ctx context.Context, handle string) (*db.User, error) {
	return s.DB.GetFiresliceUserByHandle(ctx, handle)
}

func (s *DBUserStore) ListUsers(ctx context.Context) ([]*db.User, error) {
	return s.DB.ListFiresliceUsers(ctx)
}

func (s *DBUserStore) DeleteUser(ctx context.Context, id int64) error {
	return s.DB.DeleteFiresliceUser(ctx, id)
}

func (s *DBUserStore) UpdatePassword(ctx context.Context, userID int64, password string) error {
	return s.DB.UpdateFiresliceUserPassword(ctx, userID, password)
}

func (s *DBUserStore) AddSSHKey(ctx context.Context, userID int64, publicKey, label string) (*db.SSHKey, error) {
	return s.DB.AddFiresliceSSHKey(ctx, userID, publicKey, label)
}

func (s *DBUserStore) DeleteSSHKey(ctx context.Context, userID, keyID int64) error {
	return s.DB.DeleteFiresliceSSHKey(ctx, userID, keyID)
}

func (s *DBUserStore) ListSSHKeys(ctx context.Context, userID int64) ([]*db.SSHKey, error) {
	return s.DB.ListFiresliceSSHKeys(ctx, userID)
}

type DBVMStore struct{ DB *db.DB }

func (s *DBVMStore) CreateVMRecord(ctx context.Context, input CreateVMInput) (*db.VM, error) {
	return s.DB.CreateFiresliceVM(ctx, db.FiresliceCreateVMInput{
		UserID:          input.UserID,
		Name:            input.Name,
		Image:           input.Image,
		VCPU:            input.VCPU,
		MemoryMB:        input.MemoryMB,
		DiskGB:          input.DiskGB,
		ExposeSubdomain: input.ExposeSubdomain,
		Subdomain:       input.Subdomain,
		ExposedPort:     input.ExposedPort,
	})
}

func (s *DBVMStore) GetVM(ctx context.Context, id int64) (*db.VM, error) {
	return s.DB.GetFiresliceVM(ctx, id)
}

func (s *DBVMStore) ListVMs(ctx context.Context) ([]*db.VM, error) {
	return s.DB.ListFiresliceVMs(ctx)
}

func (s *DBVMStore) ListVMsByUser(ctx context.Context, userID int64) ([]*db.VM, error) {
	return s.DB.VMsByUser(ctx, userID)
}

func (s *DBVMStore) UpdateVMStatus(ctx context.Context, id int64, status string) error {
	return s.DB.UpdateFiresliceVMStatus(ctx, id, status)
}

func (s *DBVMStore) UpdateVMExposure(ctx context.Context, id int64, expose bool, subdomain string, port int) error {
	return s.DB.UpdateFiresliceVMExposure(ctx, id, expose, subdomain, port)
}

func (s *DBVMStore) DeleteVM(ctx context.Context, id int64) error {
	return s.DB.DeleteFiresliceVM(ctx, id)
}

func (s *DBVMStore) GetVMExposure(ctx context.Context, id int64) (VMExposure, error) {
	exposure, err := s.DB.GetFiresliceVMExposure(ctx, id)
	if err != nil {
		return VMExposure{}, err
	}
	return VMExposure(exposure), nil
}

type DBAuditStore struct{ DB *db.DB }

func (s *DBAuditStore) LogAudit(ctx context.Context, action, targetType string, targetID int64, detail string) error {
	return s.DB.LogFiresliceAudit(ctx, action, targetType, targetID, detail)
}

func IsNotFound(err error) bool {
	return err == sql.ErrNoRows
}
