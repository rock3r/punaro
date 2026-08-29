# Fleet-config personal-deployment validation — 2026-08-29

## Decision and scope

- Capability: fleet-global agent configuration from issues #210–#217 plus the
  three operator additions (project-only trees, machine-local trailers, opt-in
  Claude aliases).
- Personal deployment result: **pass for live apply on the named three
  hosts plus Linux**, with Darwin HTTP reaching the LAN origin through a
  loopback forwarder (see Darwin HTTP).
- Official Internet-facing release decision: **withheld**. This record does
  not check any box in
  [`security-release-gates.md`](../security-release-gates.md).
- Operator: Seb, acting as the owner-operator of the personal self-hosted
  deployment.

## Exact candidate

- Source commit: stacked tip `agent/fleet-config-adapter-http` (based on
  `agent/fleet-config-217` `5ed2309`).
- Review reference: stacked PRs #222–#227 plus this adapter HTTP follow-up.
- Signed/tagged release reference: none.

## Hosts

| Host role | OS observed | Reachability | Platform test binary | Live HTTP apply |
| --- | --- | --- | --- | --- |
| `mac-studio` (adapter, this workstation) | Darwin arm64 | local | PASS | PASS (loopback forwarder; see Darwin HTTP) |
| `coso` (adapter) | Darwin arm64 | SSH | PASS | PASS (loopback forwarder + path override) |
| `mattone` (adapter) | Windows NT 10.0.26200 | SSH + native PowerShell | PASS | PASS (direct LAN HTTP; Windows symlink alias) |
| relay LXC (lan-test punarod + extra Linux adapter) | Linux x86_64 | SSH | PASS | PASS (direct LAN HTTP) |

`coso` is Darwin, not Linux.

## What ran

### lan-test Postgres recovery (not production)

Production Postgres remained on `127.0.0.1:5432`. lan-test was recovered onto
`127.0.0.1:15432` using the existing lan-test volume. Owner/app DSN files under
the lan-test installation were rewritten to that port only. A custom-format
dump was taken first. Schema 43 was upgraded to 59 with the shipped migrator
(`migrateConnExpectedAppRole(..., allowExistingUpgrade=true)`), refuse-closed
on any DSN port other than 15432. The `fleet` namespace exists after the
upgrade. Production schema was not migrated.

### Live lan-test publish / fetch / apply

A candidate `punarod` listened on the LAN address with health on a
non-colliding loopback port. `punaro fleet-config configure` and
`publish` of an exact fixture commit succeeded (preview then
`--yes --confirm-preview-hash`). Generation 2 republish reconverged Linux
with a surviving machine-local trailer body.

Shipped `punaro-adapter` then fetched desired metadata and the
digest-addressed archive and applied it:

- Linux LXC: direct LAN HTTP; POSIX `CLAUDE.md` symlink; status `current`.
- `mac-studio` and `coso`: same shipped Darwin adapter. Direct Go HTTP to
  `192.168.1.254:8080` completes TCP but never sends request payload
  (tcpdump: handshake only; server `ReadHeaderTimeout` FIN). `curl` and
  Apple-signed Python GET the same URL and receive `401`. A loopback
  forwarder (Apple-signed Python on Darwin) lets the adapter speak HTTP
  on `127.0.0.1` while still applying on the host filesystem. `coso` used
  an explicit project path override; an unmatched top-level name was not
  written.
- `mattone`: direct LAN HTTP after an exclusive current-user DACL on the
  sandbox profile. Native `CLAUDE.md` symlink to `AGENTS.md`. Status PUT
  returned 403 because that sandbox machine had no
  `auth.client_installations` row; apply still occurred.

### Darwin HTTP

Root cause is macOS 26 Local Network filtering of ad-hoc-signed Go
binaries: SYN/ACK succeeds, `Write` returns success, no PSH appears on
the LAN interface. Not a Punaro request-signing bug. Loopback to the
same `punarod` (SSH `-L` or Python forwarder) returns normally.

### Filesystem suite (named hosts, earlier the same day)

On each named host, the compiled `internal/fleetconfig` test binary from
`agent/fleet-config-217` passed atomic apply, last-known-good, trailer, and
Claude-alias behavior.

SSH used an on-disk identity because the 1Password SSH agent would not sign
for this agent process. Production adapter profiles were not edited.

## What did not run

- Direct (unproxied) Darwin Go HTTP to the LAN listen address. Documented
  above; apply used a loopback forwarder.
- `mattone` content-free status row (PUT 403 without an enrollment
  installation). Apply and alias were still observed on disk.
- Payload-free WebSocket wake was not separately captured; converge used
  the adapter poll interval after publish.
- Offline reconverge, revocation, corrupted-release, and interrupted apply
  on the named three hosts.
- Production schema migration, production adapter profile edit, or a new
  Internet-facing relay.

## Cleanup

- Sandbox adapters on mac-studio, coso, and the LXC were stopped.
- lan-test Postgres on 15432 and the candidate lan-test `punarod` were left
  running for further operator use; production listeners were unchanged.
- Fixture source, keys, and enrollment material remain host-local and are not
  in git.

## Residual risk

Darwin live fetch depends on a loopback forwarder until adapters are
code-signed for Local Network. Official security-release-gate boxes stay
unchecked. Production was not migrated.
