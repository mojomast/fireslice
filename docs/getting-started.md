# Getting Started With fireslice

This guide describes the current `fireslice` workflow.

## What fireslice is

`fireslice` is a small Firecracker VM control plane. It is not the old SSH-first `ussycode` product.

The current user flow is dashboard-based:

1. An admin creates your account.
2. You receive a username and password.
3. You log into the dashboard at `slice.ussyco.de`.
4. You manage your own account, SSH keys, and VMs there.

## Login

Open:

```text
https://slice.ussyco.de/login
```

If public HTTPS is not yet healthy on the host, the control plane may still only be reachable locally or behind a temporary reverse proxy.

## First Login Checklist

After logging in:

1. Open your account page.
2. Add an SSH public key.
3. Change your password if needed.
4. Create a VM.

## Creating Your First VM

Use the dashboard page:

```text
/vms/new
```

Current fields include:

- VM name
- image
- vCPU count
- memory in MB
- disk size in GB
- optional subdomain exposure settings

## Managing Your Account

Current self-service dashboard pages:

- `/`
- `/users/:id`
- `/settings`

Non-admin users are redirected from `/users` to their own account page.

## SSH Access

SSH keys are injected into the guest from the database at boot time.

That means:

- adding or removing a key affects future boots
- restarting the VM is the safe way to pick up key changes

## Web Exposure

VM web exposure is not automatic.

For a VM to be reachable publicly, all of the following must be true:

- the VM is running
- a subdomain exposure is configured
- wildcard DNS resolves `*.slice.ussyco.de`
- wildcard TLS is working on the edge
- the service inside the VM listens on `0.0.0.0:<exposed_port>`

Until that is all verified, do not assume `<subdomain>.slice.ussyco.de` works.
