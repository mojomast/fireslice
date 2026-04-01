fireslice split deployment

This deployment keeps the `fireslice` control plane in Docker while leaving Firecracker, KVM, networking, kernel assets, and VM storage on the host.

Operator files:

- `docker-compose.yml`: control plane container
- `fireslice-bastion` service: isolated SSH ingress container for slices
- `.env`: runtime configuration copied from `.env.example`
- `Caddyfile`: example host Caddy config for `slice.ussyco.de` and `*.slice.ussyco.de`

Important runtime requirements:

- `/dev/kvm`
- `/dev/net/tun`
- host networking
- `CAP_NET_ADMIN`
- host Firecracker binary mounted into the container
- host kernel image mounted into the container
- `/var/run/docker.sock` mounted so fireslice can pull/export local guest images
- host-managed persistent data under `/var/lib/fireslice`
- separate bastion host key state under `/var/lib/fireslice-bastion`

Important truthfulness constraints:

- this directory deploys the control plane, not a complete edge or host runtime
- the public control plane is intended to be served at `slice.ussyco.de`
- public SSH is intended to be served by the isolated bastion, typically `ssh.slice.ussyco.de:2222`
- you still need a host Caddy or equivalent reverse proxy terminating TLS and forwarding to `127.0.0.1:9090`
- VM exposure will not work without wildcard DNS plus wildcard TLS support
- if host Caddy is unhealthy or crashing during ACME issuance, `https://slice.ussyco.de` is still broken even if the control plane container is healthy
- if Firecracker, metadata binding, bridge/TAP setup, image import, or guest boot are incomplete, the control plane may be up while VM provisioning is still not operational

Current operator-visible access paths:

- dashboard login and management over HTTPS
- app traffic to exposed slices over wildcard HTTPS
- user SSH through the isolated bastion
- dashboard browser terminal over websocket plus guest SSH relay
