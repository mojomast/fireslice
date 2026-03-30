package vm

import (
	"context"
	"errors"
	"log/slog"
	"os"
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
