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
                   +--> Firecracker VM manager
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

### Public Routing

The control plane uses the Caddy admin API to add and remove VM routes.

That only works if the host already has:

- a healthy Caddy instance
- a reachable admin API
- wildcard DNS and wildcard TLS if VM subdomains are desired

## Historical Scope

This repository still contains older `ussycode` architecture for SSH-first flows, auth proxy behavior, and multi-node agent concepts. That material is not the current `fireslice` deployment truth unless called out explicitly.
