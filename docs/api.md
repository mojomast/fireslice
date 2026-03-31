# fireslice API Reference

The current `fireslice` API is a JSON control-plane API served by the main application.

## Base Path

```text
/api/admin
```

When publicly exposed, the intended host is:

```text
https://slice.ussyco.de/api/admin
```

## Authentication

The API relies on the same authenticated session context used by the dashboard middleware.

Current principal fields are:

- `subject`
- `user_id`
- `role`

## Authorization Model

### Admin-only

- `GET /users`
- `POST /users`
- `DELETE /users/{id}`

### Admin or self

- `GET /users/{id}`
- `POST /users/{id}/keys`
- `DELETE /users/{id}/keys/{keyID}`
- `POST /users/{id}/password`

### Admin or VM owner

- `GET /vms`
  - admin receives all VMs
  - non-admin receives only owned VMs
- `POST /vms`
  - admin may create for any `user_id`
  - non-admin is forced to their own `user_id`
- `GET /vms/{id}`
- `POST /vms/{id}/start`
- `POST /vms/{id}/stop`
- `DELETE /vms/{id}`
- `PATCH /vms/{id}/exposure`

## Endpoints

### `GET /health`

Returns:

```json
{"ok": true}
```

### `GET /users`

Admin-only. Returns all users with VM and key counts.

### `POST /users`

Admin-only. Creates a DB-backed user.

Request:

```json
{
  "handle": "bob",
  "email": "bob@example.com",
  "password": "secret123",
  "role": "user"
}
```

### `GET /users/{id}`

Admin or self. Returns one user plus keys and VM count.

### `POST /users/{id}/keys`

Admin or self. Adds an SSH key.

Request:

```json
{
  "public_key": "ssh-ed25519 AAAA... user@example",
  "label": "laptop"
}
```

### `DELETE /users/{id}/keys/{keyID}`

Admin or self. Deletes an SSH key.

### `POST /users/{id}/password`

Admin or self. Updates the user's password.

Request:

```json
{
  "password": "new-secret"
}
```

### `GET /vms`

Admin gets all VMs. Non-admin gets only owned VMs.

### `POST /vms`

Creates a VM record and, when runtime dependencies are available, attempts provisioning/start.

Request:

```json
{
  "user_id": 2,
  "name": "mybox",
  "image": "ussyuntu",
  "vcpu": 2,
  "memory_mb": 1024,
  "disk_gb": 20,
  "expose_subdomain": false
}
```

### `GET /vms/{id}`

Admin or VM owner. Returns one VM.

### `POST /vms/{id}/start`

Admin or VM owner. Starts a VM.

### `POST /vms/{id}/stop`

Admin or VM owner. Stops a VM.

### `DELETE /vms/{id}`

Admin or VM owner. Destroys a VM.

### `PATCH /vms/{id}/exposure`

Admin or VM owner. Updates subdomain exposure.

Request:

```json
{
  "expose_subdomain": true,
  "subdomain": "mybox",
  "exposed_port": 8080
}
```

## Important Limitations

- The API path still uses `/api/admin` even though some endpoints are now self-service.
- A successful control-plane API response does not prove public routing or guest service reachability.
- VM exposure still depends on real wildcard DNS, wildcard TLS, a healthy Caddy admin API, and a guest process listening on the requested port.
