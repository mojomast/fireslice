package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ioctlSIOCSIFFLAGS   = 0x8914
	ioctlSIOCSIFADDR    = 0x8916
	ioctlSIOCSIFNETMASK = 0x891c
	ioctlSIOCADDRT      = 0x890B
	iffUp               = 0x1
	ifNameSize          = 16
	afInet              = 2
	rtfUp               = 0x1
	rtfGateway          = 0x2
)

type runtimeConfig struct {
	VMName     string   `json:"vm_name"`
	WorkingDir string   `json:"working_dir"`
	Command    []string `json:"command"`
	Env        []string `json:"env"`
	GuestIP    string   `json:"guest_ip"`
	GatewayIP  string   `json:"gateway_ip"`
	SubnetBits string   `json:"subnet_bits"`
	MacAddress string   `json:"mac_address"`
}

type ifreqAddr struct {
	Name [ifNameSize]byte
	Addr syscall.RawSockaddrInet4
	Pad  [8]byte
}

type ifreqFlags struct {
	Name  [ifNameSize]byte
	Flags uint16
	Pad   [22]byte
}

type rtentry struct {
	Dst     syscall.RawSockaddrInet4
	Gateway syscall.RawSockaddrInet4
	Genmask syscall.RawSockaddrInet4
	Flags   uint16
	Pad1    int16
	Pad2    uintptr
	Pad3    uintptr
	Pad4    int16
	Iface   uintptr
	Pad5    uintptr
	Pad6    uintptr
}

func main() {
	logf("guest init starting")
	_ = writeStage("starting")
	if err := mountSpecialFS(); err != nil {
		fatal(err)
	}
	cfg, err := loadConfig("/etc/fireslice-init.json")
	if err != nil {
		fatal(err)
	}
	logf("loaded config for %s", cfg.VMName)
	_ = writeStage("config-loaded")
	if err := configureInterface("lo", net.IPv4(127, 0, 0, 1), net.CIDRMask(8, 32), nil); err != nil {
		fatal(err)
	}
	bits, err := strconv.Atoi(cfg.SubnetBits)
	if err != nil {
		fatal(err)
	}
	guestIP := net.ParseIP(cfg.GuestIP).To4()
	if guestIP == nil {
		fatal(fmt.Errorf("invalid guest ip %q", cfg.GuestIP))
	}
	mask := net.CIDRMask(bits, 32)
	gateway := net.ParseIP(cfg.GatewayIP).To4()
	if cfg.GatewayIP != "" && gateway == nil {
		fatal(fmt.Errorf("invalid gateway ip %q", cfg.GatewayIP))
	}
	if err := configureInterface("eth0", guestIP, mask, gateway); err != nil {
		fatal(err)
	}
	logf("configured eth0 %s/%d via %s", cfg.GuestIP, bits, cfg.GatewayIP)
	_ = writeStage("network-ready")
	if err := os.MkdirAll("/run/fireslice", 0755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile("/run/fireslice/state", []byte("boot\n"), 0644); err != nil {
		fatal(err)
	}
	if cfg.WorkingDir == "" {
		cfg.WorkingDir = "/"
	}
	if err := os.Chdir(cfg.WorkingDir); err != nil {
		fatal(err)
	}
	if len(cfg.Command) == 0 {
		cfg.Command = []string{"/bin/sh"}
	}
	argv0, err := exec.LookPath(cfg.Command[0])
	if err != nil {
		fatal(err)
	}
	logf("exec %s", argv0)
	_ = writeStage("exec-ready")
	env := append(os.Environ(), cfg.Env...)
	if err := syscall.Exec(argv0, cfg.Command, env); err != nil {
		fatal(err)
	}
}

func loadConfig(path string) (*runtimeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg runtimeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func mountSpecialFS() error {
	for _, mount := range []struct {
		target string
		source string
		fstype string
		data   string
	}{
		{target: "/proc", source: "proc", fstype: "proc"},
		{target: "/sys", source: "sysfs", fstype: "sysfs"},
		{target: "/dev", source: "devtmpfs", fstype: "devtmpfs", data: "mode=0755"},
		{target: "/dev/pts", source: "devpts", fstype: "devpts", data: "mode=0620,ptmxmode=0666"},
		{target: "/run", source: "tmpfs", fstype: "tmpfs", data: "mode=0755"},
		{target: "/tmp", source: "tmpfs", fstype: "tmpfs", data: "mode=1777"},
	} {
		if err := os.MkdirAll(mount.target, 0755); err != nil {
			return err
		}
		if err := syscall.Mount(mount.source, mount.target, mount.fstype, 0, mount.data); err != nil && err != syscall.EBUSY {
			return fmt.Errorf("mount %s on %s: %w", mount.fstype, mount.target, err)
		}
	}
	return nil
}

func configureInterface(name string, ip net.IP, mask net.IPMask, gateway net.IP) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := setAddr(fd, ioctlSIOCSIFADDR, name, ip); err != nil {
		return err
	}
	if err := setAddr(fd, ioctlSIOCSIFNETMASK, name, net.IP(mask)); err != nil {
		return err
	}
	if err := setFlags(fd, name, iffUp); err != nil {
		return err
	}
	if gateway != nil {
		if err := addDefaultRoute(fd, gateway); err != nil {
			return err
		}
	}
	return nil
}

func setAddr(fd int, req uintptr, name string, ip net.IP) error {
	var ifr ifreqAddr
	copy(ifr.Name[:], name)
	ifr.Addr.Family = afInet
	copy(ifr.Addr.Addr[:], ip.To4())
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

func setFlags(fd int, name string, flags uint16) error {
	var ifr ifreqFlags
	copy(ifr.Name[:], name)
	ifr.Flags = flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlSIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

func addDefaultRoute(fd int, gateway net.IP) error {
	var route rtentry
	route.Gateway.Family = afInet
	copy(route.Gateway.Addr[:], gateway.To4())
	route.Genmask.Family = afInet
	binary.BigEndian.PutUint32(route.Genmask.Addr[:], 0)
	route.Dst.Family = afInet
	binary.BigEndian.PutUint32(route.Dst.Addr[:], 0)
	route.Flags = rtfUp | rtfGateway
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlSIOCADDRT, uintptr(unsafe.Pointer(&route)))
	if errno != 0 && errno != syscall.EEXIST {
		return errno
	}
	return nil
}

func fatal(err error) {
	logf("fatal: %v", err)
	_ = writeStage("fatal:" + err.Error())
	msg := err.Error()
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	_, _ = os.Stderr.WriteString(msg)
	os.Exit(1)
}

func logf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "fireslice-guest-init: "+format+"\n", args...)
}

func writeStage(stage string) error {
	if err := os.WriteFile("/fireslice-stage", []byte(stage+"\n"), 0644); err != nil {
		return err
	}
	syscall.Sync()
	return nil
}
