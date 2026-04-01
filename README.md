# fireslice

`fireslice` is a Firecracker-based VM control plane for small operator-managed hosting.

It is a narrowed fork of the reusable infrastructure extracted from `ussycode`, with a split deployment model:

- the `fireslice` control plane runs in Docker or as a single binary
- Firecracker, KVM, networking, kernel assets, image tooling, and VM storage stay on the host
- one admin can bootstrap and manage users, quotas, SSH keys, and VMs
- users can log in with passwords and manage their own account, keys, and VMs through the dashboard

## Current Product Shape

- `cmd/fireslice` is the active entrypoint
- dashboard and API live on the same control plane
- sessions are cookie-based
- bootstrap admin auth still comes from `FIRESLICE_ADMIN_USER` and `FIRESLICE_ADMIN_PASS_BCRYPT`
- DB-backed users have `role` and `password_bcrypt`
- the dashboard is role-aware for admin vs user flows
- the `/api/admin` API now supports admin-only and admin-or-self authorization, depending on the endpoint

This repo is intentionally smaller than the old `ussycode` surface. It does not center the product around the SSH REPL, tutorial flow, exec API, email, arena/community features, or multi-node compute pool.

## What Works Today

- admin login
- DB-backed user login with bcrypt passwords
- admin user creation with role and password
- user-scoped dashboard views
- user password updates
- user SSH key management
- VM CRUD and exposure management at the control-plane level
- isolated SSH bastion access to running slices
- browser-based interactive terminal access for running slices
- split deployment artifacts for a Dockerized control plane plus host runtime dependencies

## What Is Still Incomplete

- public HTTPS for `slice.ussyco.de` is not guaranteed until the host Caddy setup is actually healthy
- wildcard VM exposure does not work without real wildcard DNS plus wildcard TLS
- VM runtime should not be treated as fully working until Firecracker, metadata, host networking, image import, and guest boot are all verified end-to-end on the host
- some older repo areas still contain legacy `ussycode` code and docs that are historical, not current fireslice behavior

## Main Components

- `cmd/fireslice`: active binary entrypoint
- `internal/fireslice`: service layer and config
- `internal/dashboard`: server-rendered HTML dashboard
- `internal/httpapi`: authenticated JSON API under `/api/admin`
- `internal/sessionauth`: login and session cookie management
- `internal/db`: SQLite schema, migrations, and fireslice CRUD helpers
- `internal/vm`: Firecracker runtime manager
- `internal/gateway`: metadata service
- `internal/proxy`: Caddy admin API route manager
- `internal/sshgate`: host-side SSH control and relay sockets for slice access
- `internal/sshbastion`: isolated bastion process for public SSH ingress

## API Summary

Base path: `/api/admin`

Admin-only endpoints:

- `GET /api/admin/health`
- `GET /api/admin/users`
- `POST /api/admin/users`
- `DELETE /api/admin/users/:id`

Admin-or-self user endpoints:

- `GET /api/admin/users/:id`
- `POST /api/admin/users/:id/keys`
- `DELETE /api/admin/users/:id/keys/:keyID`
- `POST /api/admin/users/:id/password`

Admin sees all VMs; non-admin sees/manages only owned VMs:

- `GET /api/admin/vms`
- `POST /api/admin/vms`
- `GET /api/admin/vms/:id`
- `POST /api/admin/vms/:id/start`
- `POST /api/admin/vms/:id/stop`
- `DELETE /api/admin/vms/:id`
- `PATCH /api/admin/vms/:id/exposure`

Dashboard-only slice access flows:

- SSH through the isolated bastion at `ssh.<domain>` on the configured bastion port
- browser terminal at `/vms/:id/terminal` backed by websocket-to-SSH PTY relay

## Dashboard Pages

- `/login`
- `/`
- `/users`
- `/users/:id`
- `/vms/new`
- `/vms/:id/terminal`
- `/settings`

For non-admin users, `/users` redirects to their own account page.

## Configuration

Important settings:

```bash
FIRESLICE_DOMAIN=slice.ussyco.de
FIRESLICE_HTTP_ADDR=:9090
FIRESLICE_DATA_DIR=/var/lib/fireslice
FIRESLICE_DB_PATH=/var/lib/fireslice/fireslice.db
FIRESLICE_CADDY_ADMIN=http://localhost:2019
FIRESLICE_METADATA_ADDR=:8083
FIRESLICE_BASTION_SSH_ADDR=:2222
FIRESLICE_BASTION_HTTP_ADDR=127.0.0.1:9191
FIRESLICE_SSH_CONTROL_SOCK=/var/lib/fireslice/ssh-control.sock
FIRESLICE_SSH_RELAY_SOCK=/var/lib/fireslice/ssh-relay.sock
FIRESLICE_GUEST_SSH_KEY=/var/lib/fireslice/guest_control_ed25519
FIRESLICE_FIRECRACKER_BIN=/usr/local/bin/firecracker
FIRESLICE_KERNEL=/var/lib/fireslice/vmlinux
FIRESLICE_BRIDGE=ussy0
FIRESLICE_SUBNET=10.0.0.0/24
FIRESLICE_ADMIN_USER=admin
FIRESLICE_ADMIN_PASS_BCRYPT=<bcrypt-hash>
```

## Build And Test

Use a modern Go toolchain. In the current deployment work, `/usr/local/go/bin/go` is the correct binary.

If Docker bridge DNS is broken because the host uses Tailscale's `100.100.100.100` resolver, use `--network host` for containerized Go test runs.

```bash
/usr/local/go/bin/go test ./internal/db ./internal/fireslice ./internal/httpapi ./internal/sessionauth ./internal/dashboard
/usr/local/go/bin/go build ./cmd/fireslice
```

## Deployment Notes

The intended public control plane host is `slice.ussyco.de`.

The recommended deployment model is split:

- run the control plane from `deploy/docker/fireslice-control/`
- run the isolated SSH bastion separately from the control plane
- keep Firecracker, `/dev/kvm`, `/dev/net/tun`, bridge setup, nftables, image tooling, and persistent storage on the host
- place a real host Caddy or equivalent reverse proxy in front of `127.0.0.1:9090`

Current slice access model:

- HTTPS apps use `https://<subdomain>.<domain>` when exposure is enabled
- SSH uses the isolated bastion at `ssh.<domain>` and the configured bastion port
- the browser terminal uses the same guest SSH plumbing and opens an interactive shell over websocket

Do not claim VM exposure works unless all of these are true:

- wildcard DNS resolves `*.slice.ussyco.de`
- wildcard TLS is configured and issuing successfully
- Caddy admin API is reachable by fireslice
- the guest app is actually listening on `0.0.0.0:<exposed_port>`

## Repo State

This repository still contains historical `ussycode` code and documentation for older product areas. Those files should be treated as legacy unless they explicitly mention `fireslice` and the split deployment model.

## License

[MIT](LICENSE)
