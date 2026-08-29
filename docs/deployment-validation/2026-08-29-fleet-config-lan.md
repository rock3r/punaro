# Fleet-config personal-deployment validation — 2026-08-29

## Decision and scope

- Capability: fleet-global agent configuration from issues #210–#217 plus the
  three operator additions (project-only trees, machine-local trailers, opt-in
  Claude aliases).
- Personal deployment result: **partial**. Filesystem/symlink/apply binaries
  passed on the named LAN hosts. Live publish, HTTP fetch, atomic apply,
  trailer survival, and Claude aliases were proven on a Linux adapter against
  the recovered **lan-test** relay. Darwin and Windows live HTTP apply were
  not completed.
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
| `mac-studio` (adapter, this workstation) | Darwin arm64 | local | PASS | not verified (Go HTTP to LAN listen EOF; curl/Python 401) |
| `coso` (adapter) | Darwin arm64 | SSH | PASS | not verified (same Go HTTP EOF) |
| `mattone` (adapter) | Windows NT 10.0.26200 | SSH + native PowerShell | PASS | not verified (sandbox adapter profile ACL) |
| relay LXC (lan-test punarod + extra Linux adapter) | Linux x86_64 | SSH | PASS | PASS |

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

### Live lan-test publish / fetch / apply (Linux)

A candidate `punarod` listened on the LAN address with health on a
non-colliding loopback port. `punaro fleet-config configure` and
`publish` of an exact fixture commit succeeded (preview then
`--yes --confirm-preview-hash`). A Linux adapter on the relay LXC fetched
desired metadata and the digest-addressed archive over signed HTTP, applied
the managed tree, projected matched project files, created POSIX Claude
aliases, and reported `current` without configuration contents.

A second exact-commit publish (generation 2) reconverged the same Linux
adapter. A machine-local trailer body survived. Status showed desired
generation 2, applied digest matching the new release, `trailer_state=present`,
`alias_state=linked`.

### Filesystem suite (named hosts, earlier the same day)

On each named host, the compiled `internal/fleetconfig` test binary from
`agent/fleet-config-217` passed atomic apply, last-known-good, trailer, and
Claude-alias behavior.

SSH used an on-disk identity because the 1Password SSH agent would not sign
for this agent process. Production adapter profiles were not edited.

## What did not run

- Live HTTP fetch/apply on `mac-studio` and `coso`. Unsigned Darwin binaries
  from this session get EOF against the LAN listen address; curl and Python
  from the same hosts receive the expected unauthenticated 401. This is
  recorded as unverified, not simulated.
- Live HTTP fetch/apply on `mattone`. The sandbox adapter profile failed
  closed as unsafe under Windows ACL rules.
- Payload-free WebSocket wake was not separately captured; Linux converge
  used the adapter poll interval after publish.
- Offline reconverge, revocation, corrupted-release, interrupted apply, and
  rollback of a bad desired release on the named three hosts.
- Changing the source repository without `fleet-config publish` on the named
  three hosts (Linux publish path did require an explicit publish to change
  desired state).
- Production schema migration, production adapter profile edit, or a new
  Internet-facing relay.

## Cleanup

- Sandbox adapters on mac-studio, coso, and the LXC were stopped.
- lan-test Postgres on 15432 and the candidate lan-test `punarod` were left
  running for further operator use; production listeners were unchanged.
- Fixture source, keys, and enrollment material remain host-local and are not
  in git.

## Residual risk

Named-host live HTTP apply is still unverified on Darwin and Windows.
README reorganization stays blocked until those hosts can fetch and apply, or
the operator accepts Linux-only live evidence plus the earlier filesystem
suite. Official security-release-gate boxes stay unchecked.
