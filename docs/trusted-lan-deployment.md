# Trusted-LAN deployment

This profile runs Punaro directly between machines on one operator-controlled
private or link-local network. It is a LAN release-candidate boundary, not an
Internet deployment: message bodies and device credentials cross the selected
LAN in plaintext. Machine requests remain signed and device credentials remain
server-authorized, but any machine able to observe that network can read
traffic and steal bearer credentials.

Do not port-forward the listener, publish it through a tunnel, place it on a
guest or shared Wi-Fi network, or treat NAT as an access control. The Internet
profile requires the separate Tailscale or Cloudflare Tunnel and Access work.

## Server

Choose one concrete private address and the narrowest CIDR containing every
intended client. Initialize the owner-managed deployment with the normal
digest-pinned image and protected PostgreSQL inputs, adding this explicit
ingress policy:

```sh
punaro init \
  --directory INSTALLATION_DIR \
  --data-dir DATA_DIR \
  --backup-dir BACKUP_DIR \
  --image 'REGISTRY/PUNARO@sha256:IMAGE_DIGEST' \
  --owner-dsn-file OWNER_DSN_FILE \
  --app-dsn-file APP_DSN_FILE \
  --owner-name OWNER_NAME \
  --mode lan \
  --listen-addr 192.168.1.4:8080 \
  --trusted-lan-cidr 192.168.1.0/24 \
  --allow-lan-http \
  --relay-machines-file PUBLIC_MACHINES_JSON
punaro up --directory INSTALLATION_DIR
```

The health listener remains distinct and loopback-only. PostgreSQL remains on
loopback. Restrict the host firewall to the same client CIDR and verify from a
non-member network that the device port is unreachable; Punaro also checks the
observed TCP peer against the configured CIDR and ignores forwarded headers.

## Adapter clients

The client must independently acknowledge the same plaintext boundary. The
origin must contain a literal private or link-local IP address; DNS names are
rejected for LAN HTTP so resolution cannot move credentials outside the pinned
network.

```sh
./scripts/install-client.sh \
  --relay-url http://192.168.1.4:8080 \
  --machine-id laptop-review \
  --allow-lan-http \
  --trusted-lan-cidr 192.168.1.0/24
```

On Windows use the corresponding `-AllowLanHttp` and
`-TrustedLanCidr 192.168.1.0/24` options. The installed profile records both
values. A missing, partial, public, DNS-based, or out-of-CIDR policy fails
before a relay request is sent. Ambient HTTP proxies and redirects are disabled
for plaintext LAN connections.

For device-credential enrollment, bind the same policy into the private client
identity before the server creates the invitation:

```sh
punaro-enroll prepare \
  --origin http://192.168.1.4:8080 \
  --state-dir "$HOME/.config/punaro/device-enrollment" \
  --allow-lan-http \
  --trusted-lan-cidr 192.168.1.0/24
```

Redemption and recovery reuse the persisted policy; they do not accept a
different origin or CIDR. Cloudflare Access credentials are invalid in this
profile.

Create the native memory-client profile with that same explicit policy after
the device credential has been redeemed:

```sh
punaro-memory profile-write \
  --profile "$HOME/.config/punaro/memory-profile.json" \
  --origin http://192.168.1.4:8080 \
  --credential-file "$HOME/.config/punaro/device-enrollment/device.credential" \
  --project 11111111-1111-4111-8111-111111111111 \
  --allow-lan-http \
  --trusted-lan-cidr 192.168.1.0/24
```

The protected version-2 profile records the non-secret LAN acknowledgement.
Every memory request revalidates the literal private or link-local origin and
CIDR, disables ambient proxies, and rejects redirects. HTTPS profiles remain
version 1 and need no LAN flags.

The separately enrolled Telegram bridge uses
`PUNARO_ADAPTER_ALLOW_LAN_HTTP=true` and
`PUNARO_ADAPTER_TRUSTED_LAN_CIDR=192.168.1.0/24` alongside its literal relay
URL. Telegram Bot API traffic still uses HTTPS.

## Release-candidate evidence

Before calling a commit LAN-ready, record all of the following against the
exact clean commit or image digest:

- macOS, Linux, and Windows client builds;
- server start, readiness, restart, backup, and compatible rollback;
- enrollment success, lost-response recovery, owner revocation, and rejected
  post-revocation requests;
- bidirectional delivery, acknowledgement, deduplication, reconnect, and
  durable-role replacement across real LAN hosts;
- rejection from an address outside the trusted CIDR and rejection of spoofed
  forwarded headers; and
- clean shutdown with the previous reviewed commit or image retained as the
  rollback reference.

The current source-checkout installers remain the distribution path until the
separate signed-artifact/bootstrap milestone is complete. Use a clean pinned
checkout; never pipe a downloaded installer into a shell.
