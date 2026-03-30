# fireslice Deployment Notes

`fireslice` is the stripped-down operator-managed VM platform extracted from the reusable infrastructure in the old `ussycode` codebase.

## Requirements

- Linux host
- `/dev/kvm`
- Firecracker binary
- guest kernel image
- writable data directory
- bridge/nftables permissions for VM networking
- Caddy with reachable admin API if VM exposure is enabled

## Minimum Bring-Up

1. Create a bcrypt hash for the admin password.
2. Set the `FIRESLICE_` environment variables.
3. Run database migrations automatically by starting `cmd/fireslice`.
4. Log into `/login`.
5. Create a user, add SSH keys, and create a VM.

## Important Behavior

- users do not self-provision VMs
- the operator is the only admin actor
- SSH keys are resolved from the database on VM boot
- exposure only works for running VMs
- hiding a VM removes its Caddy route but may keep the stored subdomain for reuse

## Suggested First Smoke Test

1. Start `fireslice`
2. Visit `/login`
3. Create a user
4. Add an SSH key
5. Create a VM
6. Restart the VM after adding or removing a key
7. Verify the guest authorized keys reflect the current DB state
