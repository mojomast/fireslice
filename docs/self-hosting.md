# Self-Hosting fireslice

This guide covers the current `fireslice` deployment shape.

## Supported Model

The intended deployment model is split:

- `fireslice` control plane in Docker or as a single binary
- Firecracker and low-level VM runtime dependencies on the host
- host reverse proxy in front of the control plane

## Requirements

### Host

- Linux x86_64
- `/dev/kvm`
- `/dev/net/tun`
- root access for bridge, TAP, and nftables operations
- Firecracker installed on the host
- a Firecracker-compatible guest kernel on the host
- disk space for images, disks, and runtime state

### Network

- public DNS for `slice.ussyco.de`
- wildcard DNS for `*.slice.ussyco.de` if VM exposure is desired
- ports 80 and 443 open to the host reverse proxy
- Caddy admin API reachable by `fireslice` if dynamic VM exposure is enabled
- a public hostname for the SSH bastion such as `ssh.slice.ussyco.de` if user SSH access is desired

## Recommended Layout

- control plane repo checkout: `/opt/fireslice`
- deployment operator dir: `/opt/fireslice-deploy`
- persistent data dir: `/var/lib/fireslice`
- bastion state dir: `/var/lib/fireslice-bastion`
- control plane listen addr: `127.0.0.1:9090` behind host Caddy

## Split Deployment Notes

The files under `deploy/docker/fireslice-control/` are the current starting point for Dockerized control-plane deployment.

They do not, by themselves, prove that:

- host TLS is working
- wildcard routing is working
- VM runtime is healthy
- guest provisioning is healthy

Those must be verified separately on the target host.

## Control Plane Bring-Up

At minimum, configure:

```bash
FIRESLICE_DOMAIN=slice.ussyco.de
FIRESLICE_HTTP_ADDR=:9090
FIRESLICE_DATA_DIR=/var/lib/fireslice
FIRESLICE_DB_PATH=/var/lib/fireslice/fireslice.db
FIRESLICE_CADDY_ADMIN=http://127.0.0.1:2019
FIRESLICE_METADATA_ADDR=:8083
FIRESLICE_BASTION_SSH_ADDR=:2222
FIRESLICE_BASTION_HTTP_ADDR=127.0.0.1:9191
FIRESLICE_SSH_CONTROL_SOCK=/var/lib/fireslice/ssh-control.sock
FIRESLICE_SSH_RELAY_SOCK=/var/lib/fireslice/ssh-relay.sock
FIRESLICE_GUEST_SSH_KEY=/var/lib/fireslice/guest_control_ed25519
FIRESLICE_SSH_HOST_KEY=/var/lib/fireslice-bastion/ssh_host_ed25519_key
FIRESLICE_FIRECRACKER_BIN=/usr/local/bin/firecracker
FIRESLICE_KERNEL=/boot/vmlinux-fireslice
FIRESLICE_BRIDGE=ussy0
FIRESLICE_SUBNET=10.0.0.0/24
FIRESLICE_ADMIN_USER=admin
FIRESLICE_ADMIN_PASS_BCRYPT=<bcrypt-hash>
```

## Public Edge

To make `https://slice.ussyco.de` work, the host needs a healthy edge proxy.

Typical shape:

- host Caddy listens on 80 and 443
- `slice.ussyco.de` reverse proxies to `127.0.0.1:9090`
- Caddy admin API is reachable at `127.0.0.1:2019`

If Caddy is crashing during ACME issuance, the control plane may still work locally while public HTTPS remains broken.

## Slice SSH And Terminal Access

Running slices are accessed in three different ways:

- public web traffic through `https://<subdomain>.<domain>` when exposure is enabled
- SSH through the isolated bastion, typically `ssh -p 2222 <slice-name>@ssh.slice.ussyco.de`
- browser terminal through the dashboard at `/vms/:id/terminal`

Important constraints:

- the bastion should stay isolated from the host and should only proxy to slice `:22`
- the control plane needs access to the SSH control and relay sockets
- the guest image does not need a packaged `sshd`; fireslice injects the guest SSH helper at runtime

## VM Exposure Requirements

Public VM subdomains require all of the following:

- wildcard DNS for `*.slice.ussyco.de`
- wildcard TLS support on the edge
- Caddy admin API access from fireslice
- a running VM with valid IP and exposure settings
- a guest service listening on `0.0.0.0:<exposed_port>`

## Historical Note

Older `ussycode` deployment docs in this repository are historical and should not be followed for current `fireslice` deployment unless they have been explicitly rewritten.
