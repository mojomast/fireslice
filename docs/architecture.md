# fireslice Architecture

## Overview

`fireslice` is a small control plane for Firecracker VMs with a split deployment model.

```text
Internet
   |
   +--> Host Caddy / HTTPS edge
           |
           +--> fireslice control plane (:9090)
                    |
                    +--> dashboard
                    +--> /api/admin
                    +--> session auth
                    +--> SQLite
                    +--> metadata service
                    +--> Caddy admin API route manager
                    +--> ssh control socket
                    +--> ssh relay socket
                    +--> Firecracker VM manager

Internet
   |
   +--> isolated SSH bastion (:2222 or configured port)
           |
           +--> ssh control socket
           +--> ssh relay socket
           +--> guest SSH on running slice
```

## Main Pieces

### Control Plane

The control plane is served by `cmd/fireslice`.

It wires together:

- SQLite DB
- dashboard handlers
- JSON API handlers
- session auth
- metadata server
- optional Firecracker runtime manager
- optional Caddy route manager

### Dashboard

The dashboard is a server-rendered HTML app.

Current roles:

- admin: can manage all users and VMs
- user: can manage only owned account state and owned VMs

The dashboard also exposes:

- VM detail pages with public URL and SSH instructions
- an interactive browser terminal page that bridges websocket input/output to a guest SSH PTY session

### API

The JSON API lives under `/api/admin`.

Despite the path name, current behavior is mixed:

- some endpoints are admin-only
- some endpoints allow admin or self / admin or owner access

### Database

SQLite stores:

- users
- bcrypt password hashes
- roles
- SSH keys
- VMs
- VM exposure settings
- audit events

### VM Runtime

The VM runtime depends on host reality:

- Firecracker binary
- `/dev/kvm`
- TAP interfaces and bridge attachment
- nftables
- metadata service routing
- guest image import and disk creation tooling

The control plane can come up even when the runtime is not fully usable.

### Slice SSH Path

SSH access is intentionally split from the HTTPS control plane.

- a dedicated bastion process accepts public SSH connections
- bastion key auth resolves the caller to an owned VM through the control socket
- bastion and dashboard terminal sessions connect to the guest through a restricted relay socket that only permits guest port `22`
- the guest runs a small injected SSH helper rather than depending on a distro `sshd` package

### Public Routing

The control plane uses the Caddy admin API to add and remove VM routes.

That only works if the host already has:

- a healthy Caddy instance
- a reachable admin API
- wildcard DNS and wildcard TLS if VM subdomains are desired

## Historical Scope

This repository still contains older `ussycode` architecture for SSH-first flows, auth proxy behavior, and multi-node agent concepts. That material is not the current `fireslice` deployment truth unless called out explicitly.
