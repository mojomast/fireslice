package vm

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerCreateAndStartWithOptionsValidation(t *testing.T) {
	t.Parallel()

	manager := &Manager{logger: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	ctx := context.Background()

	tests := []struct {
		name    string
		opts    CreateOptions
		wantErr string
	}{
		{
			name:    "missing vm id",
			opts:    CreateOptions{Name: "vm", ImageRef: "ussyuntu", VCPU: 1, MemoryMB: 512, DataDiskGB: 10},
			wantErr: "vm_id must be greater than zero",
		},
		{
			name:    "missing name",
			opts:    CreateOptions{VMID: 1, ImageRef: "ussyuntu", VCPU: 1, MemoryMB: 512, DataDiskGB: 10},
			wantErr: "name is required",
		},
		{
			name:    "missing image ref",
			opts:    CreateOptions{VMID: 1, Name: "vm", VCPU: 1, MemoryMB: 512, DataDiskGB: 10},
			wantErr: "image_ref is required",
		},
		{
			name:    "invalid vcpu",
			opts:    CreateOptions{VMID: 1, Name: "vm", ImageRef: "ussyuntu", MemoryMB: 512, DataDiskGB: 10},
			wantErr: "vcpu must be greater than zero",
		},
		{
			name:    "invalid memory",
			opts:    CreateOptions{VMID: 1, Name: "vm", ImageRef: "ussyuntu", VCPU: 1, DataDiskGB: 10},
			wantErr: "memory_mb must be greater than zero",
		},
		{
			name:    "invalid disk size",
			opts:    CreateOptions{VMID: 1, Name: "vm", ImageRef: "ussyuntu", VCPU: 1, MemoryMB: 512},
			wantErr: "data_disk_gb must be greater than zero",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := manager.CreateAndStartWithOptions(ctx, tc.opts)
			if err == nil {
				t.Fatalf("CreateAndStartWithOptions() error = nil, want %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CreateAndStartWithOptions() error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestManagerCreateDataDiskPropagatesConfiguredSize(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	disksDir := filepath.Join(dataDir, "disks")
	if err := os.MkdirAll(disksDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	manager := &Manager{dataDir: dataDir}

	original := createEmptyExt4Func
	t.Cleanup(func() {
		createEmptyExt4Func = original
	})

	var gotPath string
	var gotSize int64
	createEmptyExt4Func = func(_ context.Context, path string, sizeBytes int64) error {
		gotPath = path
		gotSize = sizeBytes
		return nil
	}

	path, err := manager.createDataDisk(context.Background(), 42, 20)
	if err != nil {
		t.Fatalf("createDataDisk() error = %v", err)
	}

	wantPath := filepath.Join(disksDir, "vm-42-data.ext4")
	if path != wantPath {
		t.Fatalf("createDataDisk() path = %q, want %q", path, wantPath)
	}
	if gotPath != wantPath {
		t.Fatalf("createEmptyExt4() path = %q, want %q", gotPath, wantPath)
	}

	const wantSize = int64(20) * 1024 * 1024 * 1024
	if gotSize != wantSize {
		t.Fatalf("createEmptyExt4() size = %d, want %d", gotSize, wantSize)
	}
}

func TestManagerCreateDataDiskRejectsInvalidSize(t *testing.T) {
	t.Parallel()

	manager := &Manager{dataDir: t.TempDir()}

	original := createEmptyExt4Func
	t.Cleanup(func() {
		createEmptyExt4Func = original
	})

	called := false
	createEmptyExt4Func = func(context.Context, string, int64) error {
		called = true
		return errors.New("should not be called")
	}

	_, err := manager.createDataDisk(context.Background(), 7, 0)
	if err == nil {
		t.Fatal("createDataDisk() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "data_disk_gb must be greater than zero") {
		t.Fatalf("createDataDisk() error = %q, want disk validation error", err.Error())
	}
	if called {
		t.Fatal("createEmptyExt4() was called for invalid disk size")
	}
}

func TestProvisioningContextIgnoresParentCancellation(t *testing.T) {
	t.Parallel()

	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()

	ctx, cancel := provisioningContext(parent)
	defer cancel()

	if err := ctx.Err(); err != nil {
		t.Fatalf("provisioningContext() err = %v, want active context", err)
	}
	if deadline, ok := ctx.Deadline(); !ok || deadline.IsZero() {
		t.Fatal("provisioningContext() missing deadline")
	}
}

func TestRewriteExt4FileIfExistsSkipsMissingPath(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 not installed")
	}
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs not installed")
	}

	rootfs := filepath.Join(t.TempDir(), "rootfs.ext4")
	f, err := os.Create(rootfs)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := f.Truncate(16 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Truncate() error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	cmd := exec.Command("mkfs.ext4", "-F", "-q", rootfs)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4 error = %v, output = %s", err, string(out))
	}

	called := false
	err = rewriteExt4FileIfExists(context.Background(), rootfs, "/missing", 0, 0, "0100644", func(s string) string {
		called = true
		return s + "changed"
	})
	if err != nil {
		t.Fatalf("rewriteExt4FileIfExists() error = %v", err)
	}
	if called {
		t.Fatal("rewriteExt4FileIfExists() called mutate for missing path")
	}
}

func TestFirecrackerStayedRunningReturnsFalseForNil(t *testing.T) {
	t.Parallel()

	if firecrackerStayedRunning(nil, 0) {
		t.Fatal("firecrackerStayedRunning(nil) = true, want false")
	}
}
