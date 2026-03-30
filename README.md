# fireslice

`fireslice` is a stripped-down operator-managed VM hosting platform built on top of the reusable Firecracker, SQLite, metadata, networking, and Caddy pieces extracted from `ussycode`.

It is intentionally narrower than the original product:

- one operator/admin
- many managed users
- each VM belongs to one user
- users authenticate with SSH keys injected into their VM
- operator creates, starts, stops, destroys, exposes, and hides VMs
- management happens through a small dashboard and admin-only REST API

## What It Does

`fireslice` is for running friend-managed personal VMs without the rest of the old product surface.

Primary workflow:

1. Operator logs into the dashboard.
2. Operator creates a user.
3. Operator adds one or more SSH public keys for that user.
4. Operator creates a VM with CPU, RAM, disk, and optional exposure settings.
5. User SSHs directly into that VM.
6. Operator can later start, stop, destroy, expose, or hide it.

## Reused Infrastructure

This repo reuses the parts of the old system that were already reality-based and working well:

- Firecracker VM runtime
- TAP/bridge/nftables networking
- SQLite models and migrations
- metadata service for boot-time guest configuration
- Caddy admin API route management
- `ussyuntu` guest image bootstrap

It does not build the product around the old SSH REPL, tutorial flow, exec API, email, community features, or cluster features.

## Main Components

- `cmd/fireslice`: stripped-down binary
- `internal/fireslice`: shared service layer and config
- `internal/httpapi`: admin REST API under `/api/admin`
- `internal/dashboard`: minimal HTML dashboard
- `internal/sessionauth`: admin login and session cookies
- `internal/db`: reused schema plus fireslice-specific CRUD helpers
- `internal/vm`: Firecracker manager with options-based create/start path
- `internal/gateway`: metadata server that resolves the current owner keys from DB
- `internal/proxy`: Caddy route manager used for public VM exposure

## Admin API

Base path: `/api/admin`

Current endpoints:

- `GET /api/admin/health`
- `GET /api/admin/users`
- `POST /api/admin/users`
- `GET /api/admin/users/:id`
- `DELETE /api/admin/users/:id`
- `POST /api/admin/users/:id/keys`
- `DELETE /api/admin/users/:id/keys/:keyID`
- `GET /api/admin/vms`
- `POST /api/admin/vms`
- `GET /api/admin/vms/:id`
- `POST /api/admin/vms/:id/start`
- `POST /api/admin/vms/:id/stop`
- `DELETE /api/admin/vms/:id`
- `PATCH /api/admin/vms/:id/exposure`

All endpoints are admin-authenticated.

## Dashboard

Current pages:

- `/login`
- `/`
- `/users`
- `/users/:id`
- `/vms/new`
- `/settings`

The dashboard is intentionally minimal and server-rendered with `html/template`.

## Configuration

`fireslice` uses `FIRESLICE_` environment variables or equivalent flags.

Important settings:

```bash
FIRESLICE_DOMAIN=slice.ussyco.de
FIRESLICE_HTTP_ADDR=:9090
FIRESLICE_DATA_DIR=/var/lib/fireslice
FIRESLICE_DB_PATH=/var/lib/fireslice/fireslice.db
FIRESLICE_CADDY_ADMIN=http://localhost:2019
FIRESLICE_METADATA_ADDR=:8083
FIRESLICE_FIRECRACKER_BIN=/usr/local/bin/firecracker
FIRESLICE_KERNEL=/var/lib/fireslice/vmlinux
FIRESLICE_BRIDGE=ussy0
FIRESLICE_SUBNET=10.0.0.0/24
FIRESLICE_ADMIN_USER=admin
FIRESLICE_ADMIN_PASS_BCRYPT=<bcrypt-hash>
```

## Build

```bash
go build ./cmd/fireslice
```

## Run

```bash
FIRESLICE_DOMAIN=slice.ussyco.de \
FIRESLICE_ADMIN_USER=admin \
FIRESLICE_ADMIN_PASS_BCRYPT='<bcrypt-hash>' \
go run ./cmd/fireslice
```

## Test

Focused package verification used during integration:

```bash
go test ./internal/db ./internal/fireslice ./internal/httpapi ./internal/vm ./internal/gateway ./internal/sessionauth ./internal/dashboard
go build ./cmd/fireslice
```

## Runtime Notes

- Firecracker and VM networking still require a Linux host with the right privileges.
- The dashboard/control plane can start even if VM provisioning dependencies are missing, but VM lifecycle actions will not work until Firecracker, kernel, bridge, and Caddy are available.
- VM exposure is backed by Caddy routes and only succeeds for running VMs.
- Boot-time SSH key injection resolves keys from the current VM owner in the database, so key changes take effect on restart.

## Repository Origin

This repository was split from `mojomast/ussycode` to ship the narrower `fireslice` product as its own standalone codebase.

## License

[MIT](LICENSE)
