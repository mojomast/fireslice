# fireslice Status Spec

This file replaces the old `ussycode` product spec as the current high-level truth for this repository.

## Current Scope

`fireslice` is a Firecracker VM control plane for small operator-managed or admin-bootstrapped hosting.

Current intended shape:

- public control plane host: `slice.ussyco.de`
- split deployment: control plane in Docker, runtime dependencies on the host
- bootstrap admin from environment
- DB-backed users with passwords and roles
- dashboard-based self-service for normal users
- JSON API for admin and self-service account/VM operations

## Current Working Areas

- `cmd/fireslice`
- SQLite migrations and fireslice CRUD helpers
- session auth with bootstrap admin plus DB-backed users
- role-aware dashboard
- user password updates
- user-scoped dashboard and API authorization
- control-plane Docker deployment artifacts

## Current Known Gaps

- public HTTPS depends on a healthy host edge proxy
- wildcard VM exposure depends on real wildcard DNS and wildcard TLS
- VM runtime truth still requires real host validation
- some legacy `ussycode` areas remain in the tree and are not current product truth

## Current Priority Order

1. Keep docs and repository metadata truthful.
2. Keep admin and self-service auth paths correct.
3. Make `slice.ussyco.de` work reliably as a public HTTPS control plane.
4. Make VM provisioning and VM exposure true in host reality.
5. Only then expand product surface further.
