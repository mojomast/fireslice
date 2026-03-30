package vm

// CreateOptions is the fireslice-facing VM creation contract.
type CreateOptions struct {
	VMID       int64
	Name       string
	ImageRef   string
	VCPU       int
	MemoryMB   int
	DataDiskGB int
	SSHKeys    []string
	Env        map[string]string
}
