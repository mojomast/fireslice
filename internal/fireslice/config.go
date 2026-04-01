package fireslice

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Config holds the minimal runtime configuration for the stripped-down
// fireslice binary.
type Config struct {
	Domain          string
	HTTPListenAddr  string
	SSHRelaySock    string
	SSHControlSock  string
	BastionHTTPAddr string
	BastionSSHAddr  string
	SSHHostKeyPath  string
	GuestSSHKeyPath string
	DataDir         string
	DBPath          string
	CaddyAdminAddr  string
	MetadataAddr    string
	FirecrackerBin  string
	KernelPath      string
	InitrdPath      string
	NetworkBridge   string
	NetworkSubnet   string
	AdminUsername   string
	AdminPassBcrypt string
	Debug           bool
}

func DefaultConfig() *Config {
	dataDir := envOrDefault("FIRESLICE_DATA_DIR", "/var/lib/fireslice")

	return &Config{
		Domain:          envOrDefault("FIRESLICE_DOMAIN", "local.test"),
		HTTPListenAddr:  envOrDefault("FIRESLICE_HTTP_ADDR", ":9090"),
		SSHRelaySock:    envOrDefault("FIRESLICE_SSH_RELAY_SOCK", filepath.Join(dataDir, "ssh-relay.sock")),
		SSHControlSock:  envOrDefault("FIRESLICE_SSH_CONTROL_SOCK", filepath.Join(dataDir, "ssh-control.sock")),
		BastionHTTPAddr: envOrDefault("FIRESLICE_BASTION_HTTP_ADDR", ":9191"),
		BastionSSHAddr:  envOrDefault("FIRESLICE_BASTION_SSH_ADDR", ":2222"),
		SSHHostKeyPath:  envOrDefault("FIRESLICE_SSH_HOST_KEY", "/var/lib/fireslice-bastion/ssh_host_ed25519_key"),
		GuestSSHKeyPath: envOrDefault("FIRESLICE_GUEST_SSH_KEY", filepath.Join(dataDir, "guest_control_ed25519")),
		DataDir:         dataDir,
		DBPath:          envOrDefault("FIRESLICE_DB_PATH", filepath.Join(dataDir, "fireslice.db")),
		CaddyAdminAddr:  envOrDefault("FIRESLICE_CADDY_ADMIN", "http://localhost:2019"),
		MetadataAddr:    envOrDefault("FIRESLICE_METADATA_ADDR", ":8083"),
		FirecrackerBin:  envOrDefault("FIRESLICE_FIRECRACKER_BIN", "firecracker"),
		KernelPath:      envOrDefault("FIRESLICE_KERNEL", filepath.Join(dataDir, "vmlinux")),
		InitrdPath:      envWithFallback("FIRESLICE_INITRD", ""),
		NetworkBridge:   envOrDefault("FIRESLICE_BRIDGE", "ussy0"),
		NetworkSubnet:   envOrDefault("FIRESLICE_SUBNET", "10.0.0.0/24"),
		AdminUsername:   envOrDefault("FIRESLICE_ADMIN_USER", "admin"),
		AdminPassBcrypt: envOrDefault("FIRESLICE_ADMIN_PASS_BCRYPT", ""),
		Debug:           envOrDefaultBool("FIRESLICE_DEBUG", false),
	}
}

func (c *Config) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.Domain, "domain", c.Domain, "Base domain for VM subdomains")
	fs.StringVar(&c.HTTPListenAddr, "http-addr", c.HTTPListenAddr, "HTTP listen address for dashboard and admin API")
	fs.StringVar(&c.SSHRelaySock, "ssh-relay-sock", c.SSHRelaySock, "Unix socket for restricted slice SSH relay")
	fs.StringVar(&c.SSHControlSock, "ssh-control-sock", c.SSHControlSock, "Unix socket for bastion control-plane lookups")
	fs.StringVar(&c.BastionHTTPAddr, "bastion-http-addr", c.BastionHTTPAddr, "HTTP listen address for isolated SSH bastion")
	fs.StringVar(&c.BastionSSHAddr, "bastion-ssh-addr", c.BastionSSHAddr, "SSH listen address for isolated bastion")
	fs.StringVar(&c.SSHHostKeyPath, "ssh-host-key", c.SSHHostKeyPath, "SSH bastion host key file path")
	fs.StringVar(&c.GuestSSHKeyPath, "guest-ssh-key", c.GuestSSHKeyPath, "Guest control SSH key file path")
	fs.StringVar(&c.DataDir, "data-dir", c.DataDir, "Root data directory")
	fs.StringVar(&c.DBPath, "db", c.DBPath, "SQLite database path")
	fs.StringVar(&c.CaddyAdminAddr, "caddy-api", c.CaddyAdminAddr, "Caddy admin API URL")
	fs.StringVar(&c.MetadataAddr, "metadata-addr", c.MetadataAddr, "Metadata service listen address")
	fs.StringVar(&c.FirecrackerBin, "firecracker", c.FirecrackerBin, "Path to firecracker binary")
	fs.StringVar(&c.KernelPath, "kernel", c.KernelPath, "Path to guest kernel")
	fs.StringVar(&c.InitrdPath, "initrd", c.InitrdPath, "Path to guest initrd")
	fs.StringVar(&c.NetworkBridge, "bridge", c.NetworkBridge, "Bridge interface for VM networking")
	fs.StringVar(&c.NetworkSubnet, "subnet", c.NetworkSubnet, "CIDR subnet for VM IPs")
	fs.StringVar(&c.AdminUsername, "admin-user", c.AdminUsername, "Admin username for dashboard login")
	fs.StringVar(&c.AdminPassBcrypt, "admin-pass-bcrypt", c.AdminPassBcrypt, "Bcrypt password hash for admin login")
	fs.BoolVar(&c.Debug, "debug", c.Debug, "Enable debug logging")
}

func (c *Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("config: domain is required (set FIRESLICE_DOMAIN or -domain)")
	}
	if c.DataDir == "" {
		return fmt.Errorf("config: data directory is required (set FIRESLICE_DATA_DIR or -data-dir)")
	}
	if c.DBPath == "" {
		return fmt.Errorf("config: database path is required (set FIRESLICE_DB_PATH or -db)")
	}
	if c.HTTPListenAddr == "" {
		return fmt.Errorf("config: HTTP listen address is required (set FIRESLICE_HTTP_ADDR or -http-addr)")
	}
	return nil
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envWithFallback(key, defaultVal string) string {
	v, ok := os.LookupEnv(key)
	if ok {
		return v
	}
	return defaultVal
}

func envOrDefaultBool(key string, defaultVal bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return defaultVal
	}
	return parsed
}
