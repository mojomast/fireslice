# fireslice Deployment Notes

`fireslice` is the stripped-down VM control plane extracted from the reusable infrastructure in the old `ussycode` codebase.

## Requirements

- Linux host
- `/dev/kvm`
- `/dev/net/tun`
- Firecracker binary
- guest kernel image compatible with Firecracker
- writable data directory
- bridge and nftables permissions for VM networking
- Caddy with reachable admin API if VM exposure is enabled
- Docker available on the host if you use OCI image export paths

## Minimum Bring-Up

1. Create a bcrypt hash for the bootstrap admin password.
2. Set the `FIRESLICE_` environment variables.
3. Start `cmd/fireslice` or the Dockerized control plane.
4. Let the app run migrations automatically.
5. Log into `/login` as the bootstrap admin.
6. Create a user with a password and role.
7. Add an SSH key and create a VM for that user.
8. Confirm the user can reach the slice through the SSH bastion or dashboard terminal once it is running.

## Important Behavior

- the bootstrap admin is still environment-configured
- DB-backed users can log in with username and password
- non-admin users can manage their own account, password, keys, and VMs in the dashboard
- the operator/admin remains the only actor who can list all users and create/delete arbitrary users
- SSH keys are resolved from the database on VM boot
- SSH to slices is exposed through a separate isolated bastion, not by publishing guest port 22 directly
- the dashboard browser terminal now opens an interactive shell over websocket plus the same guest SSH relay path
- exposure only works for running VMs
- hiding a VM removes its Caddy route but may keep the stored subdomain for reuse

## Current Limitations

- `slice.ussyco.de` is the intended public control plane hostname, but public HTTPS depends on a healthy host Caddy deployment
- wildcard VM exposure still requires real wildcard DNS and wildcard TLS
- VM runtime status should not be treated as complete until Firecracker, metadata, bridge/TAP setup, nftables, image import, and guest boot all succeed on the target host

## Suggested Smoke Test

1. Start `fireslice`
2. Visit `/login`
3. Log in as the bootstrap admin
4. Create a normal user with a password
5. Log in as that user in a separate session
6. Confirm the user can access `/settings` and their own `/users/:id` page
7. Update the user password and verify the new password works
8. Create a VM and confirm it appears only in that user's view unless you are logged in as admin
9. Add an SSH key, then verify the VM detail page shows the bastion SSH command and terminal link
10. Open `/vms/:id/terminal` and confirm you get an interactive shell once the slice is running
