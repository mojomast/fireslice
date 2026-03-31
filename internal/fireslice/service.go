package fireslice

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"

	"github.com/mojomast/fireslice/internal/db"
	"github.com/mojomast/fireslice/internal/gateway"
	"github.com/mojomast/fireslice/internal/vm"
)

type Service struct {
	Users  UserStore
	VMs    VMStore
	VMRun  VMRuntime
	Routes RouteManager
	Audit  AuditStore
	Images ImageStore
	Meta   MetadataManager
	Domain string
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
	if err := s.validateCreateVMResources(ctx, input); err != nil {
		return nil, err
	}
	if err := s.validateImageSelection(ctx, input.Image); err != nil {
		return nil, err
	}
	vmRecord, err := s.VMs.CreateVMRecord(ctx, input)
	if err != nil {
		return nil, err
	}

	if s.VMRun != nil {
		keys, err := s.userKeys(ctx, input.UserID)
		if err != nil {
			_ = s.VMs.DeleteVM(ctx, vmRecord.ID)
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
			_ = s.VMs.DeleteVM(ctx, vmRecord.ID)
			return nil, err
		}
		vmRecord.Status = "running"
	}

	if err := s.syncMetadataRegistration(ctx, vmRecord.ID); err != nil {
		if s.VMRun != nil {
			_ = s.VMRun.Destroy(ctx, vmRecord.ID)
		}
		_ = s.VMs.DeleteVM(ctx, vmRecord.ID)
		return nil, err
	}

	if input.ExposeSubdomain {
		if err := s.ExposeVM(ctx, vmRecord.ID, input.Subdomain, input.ExposedPort); err != nil {
			if s.VMRun != nil {
				_ = s.VMRun.Destroy(ctx, vmRecord.ID)
			}
			_ = s.VMs.DeleteVM(ctx, vmRecord.ID)
			return nil, err
		}
	}

	_ = s.logAudit(ctx, "vm.created", "vm", vmRecord.ID, vmRecord.Name)
	return s.VMs.GetVM(ctx, vmRecord.ID)
}

func (s *Service) validateImageSelection(ctx context.Context, imageRef string) error {
	if s.Images == nil {
		return nil
	}
	images, err := s.Images.ListImages(ctx)
	if err != nil {
		return err
	}
	for _, image := range images {
		if image.Ref == imageRef {
			return nil
		}
	}
	return fmt.Errorf("image is not available")
}

func (s *Service) validateCreateVMResources(ctx context.Context, input CreateVMInput) error {
	if s.Users == nil || s.VMs == nil {
		return nil
	}
	user, err := s.Users.GetUser(ctx, input.UserID)
	if err != nil {
		return err
	}
	vms, err := s.VMs.ListVMsByUser(ctx, input.UserID)
	if err != nil {
		return err
	}
	totalCPU := input.VCPU
	totalRAMMB := input.MemoryMB
	totalDiskMB := input.DiskGB * 1024
	for _, existing := range vms {
		totalCPU += existing.VCPU
		totalRAMMB += existing.MemoryMB
		totalDiskMB += existing.DiskGB * 1024
	}
	if user.VMLimit >= 0 && len(vms) >= user.VMLimit {
		return fmt.Errorf("vm quota exceeded")
	}
	if user.CPULimit >= 0 && totalCPU > user.CPULimit {
		return fmt.Errorf("cpu quota exceeded")
	}
	if user.RAMLimitMB >= 0 && totalRAMMB > user.RAMLimitMB {
		return fmt.Errorf("memory quota exceeded")
	}
	if user.DiskLimitMB >= 0 && totalDiskMB > user.DiskLimitMB {
		return fmt.Errorf("disk quota exceeded")
	}
	return nil
}

func (s *Service) UpdateUserQuotas(ctx context.Context, userID int64, trustLevel string, vmLimit, cpuLimit, ramLimitMB, diskLimitMB int) error {
	if s.Users == nil {
		return fmt.Errorf("user store unavailable")
	}
	trustLevel = strings.TrimSpace(trustLevel)
	if trustLevel == "" {
		return fmt.Errorf("trust level is required")
	}
	if !db.IsValidTrustLevel(trustLevel) {
		return fmt.Errorf("invalid trust level %q", trustLevel)
	}
	limits := []struct {
		name  string
		value int
	}{
		{name: "vm_limit", value: vmLimit},
		{name: "cpu_limit", value: cpuLimit},
		{name: "ram_limit_mb", value: ramLimitMB},
		{name: "disk_limit_mb", value: diskLimitMB},
	}
	for _, limit := range limits {
		if limit.value == 0 || limit.value < -1 {
			return fmt.Errorf("%s must be positive or -1", limit.name)
		}
	}
	if err := s.Users.UpdateQuotas(ctx, userID, trustLevel, vmLimit, cpuLimit, ramLimitMB, diskLimitMB); err != nil {
		return err
	}
	return s.logAudit(ctx, "user.quotas_updated", "user", userID, trustLevel)
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
	if err := s.syncMetadataRegistration(ctx, id); err != nil {
		_ = s.VMRun.Stop(ctx, id)
		_ = s.VMs.UpdateVMStatus(ctx, id, "stopped")
		return err
	}
	vmRecord, err = s.VMs.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vmRecord.ExposeSubdomain {
		if err := s.addRoute(ctx, vmRecord); err != nil {
			s.unregisterMetadata(vmRecord)
			_ = s.VMRun.Stop(ctx, id)
			_ = s.VMs.UpdateVMStatus(ctx, id, "stopped")
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
		if err := s.removeRoute(ctx, vmRecord); err != nil {
			return err
		}
	}
	if err := s.VMRun.Stop(ctx, id); err != nil {
		return err
	}
	s.unregisterMetadata(vmRecord)
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
		if err := s.removeRoute(ctx, vmRecord); err != nil {
			return err
		}
	}
	s.unregisterMetadata(vmRecord)
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
		_ = s.VMs.UpdateVMExposure(ctx, id, false, "", vmRecord.ExposedPort)
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
		if err := s.removeRoute(ctx, vmRecord); err != nil {
			return err
		}
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

func (s *Service) syncMetadataRegistration(ctx context.Context, vmID int64) error {
	if s.Meta == nil || s.VMs == nil || s.Users == nil {
		return nil
	}
	vmRecord, err := s.VMs.GetVM(ctx, vmID)
	if err != nil {
		return err
	}
	if !vmRecord.IPAddress.Valid {
		return fmt.Errorf("vm ip address is not available")
	}
	user, err := s.Users.GetUser(ctx, vmRecord.UserID)
	if err != nil {
		return err
	}
	meta := &gateway.VMMetadata{
		InstanceID: fmt.Sprintf("vm-%d", vmRecord.ID),
		LocalIPv4:  vmRecord.IPAddress.String,
		Hostname:   vmRecord.Name,
		UserID:     user.ID,
		UserHandle: user.Handle,
		VMName:     vmRecord.Name,
		Image:      vmRecord.Image,
		Gateway:    metadataGateway(vmRecord.IPAddress.String),
	}
	s.Meta.RegisterVM(vmRecord.IPAddress.String, meta)
	return nil
}

func metadataGateway(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "10.0.0.1"
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "10.0.0.1"
	}
	return fmt.Sprintf("%d.%d.%d.1", v4[0], v4[1], v4[2])
}

func (s *Service) unregisterMetadata(vmRecord *db.VM) {
	if s.Meta == nil || vmRecord == nil || !vmRecord.IPAddress.Valid {
		return
	}
	s.Meta.UnregisterVM(vmRecord.IPAddress.String)
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

func (s *DBUserStore) UpdateQuotas(ctx context.Context, userID int64, trustLevel string, vmLimit, cpuLimit, ramLimitMB, diskLimitMB int) error {
	return s.DB.UpdateFiresliceUserQuotas(ctx, userID, trustLevel, vmLimit, cpuLimit, ramLimitMB, diskLimitMB)
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
