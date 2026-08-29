# Fleet-config personal-deployment validation — 2026-08-29

## Decision and scope

- Capability: fleet-global agent configuration from issues #210–#217 plus the
  three operator additions (project-only trees, machine-local trailers, opt-in
  Claude aliases).
- Personal deployment result: **partial**. Real platform execution of the
  shipped `internal/fleetconfig` test binary passed on the named LAN hosts.
  End-to-end publish, payload-free wake, HTTP fetch, and adapter apply against
  the live enrolled adapters were **not** run.
- Official Internet-facing release decision: **withheld**. This record does
  not check any box in
  [`security-release-gates.md`](../security-release-gates.md).
- Operator: Seb, acting as the owner-operator of the personal self-hosted
  deployment.

## Exact candidate

- Source commit: `43aa48a64577304dac55d83d33bef7badf6cc44e`
  (`agent/fleet-config-217`).
- Review reference: stacked PRs #222–#227.
- Signed/tagged release reference: none.

## Hosts

| Host role | OS observed | Reachability | Platform test binary |
| --- | --- | --- | --- |
| `mac-studio` (adapter, this workstation) | Darwin arm64 | local | PASS |
| `coso` (adapter) | Darwin arm64 | SSH | PASS |
| `mattone` (adapter) | Windows NT 10.0.26200 | SSH + native PowerShell | PASS |
| relay LXC (server only; not a named client) | Linux x86_64 | SSH | PASS (extra Linux FS run) |

`coso` is Darwin, not Linux. The named three-host fleet therefore exercised
two macOS clients and one Windows client. Linux filesystem behavior was
exercised on the relay LXC in a disposable temp directory only.

## What ran

On each host, the compiled `internal/fleetconfig` test binary from the
candidate was executed (`go test -c`, then the binary). That binary contains
the shipped validation, materialize, trailer, project-match, atomic publish,
last-known-good, and Claude-alias functions. Results:

- Atomic apply and last-known-good restore: pass on Darwin, Linux, and Windows.
- Live-tree symlink rejection: pass on Darwin and Linux (Windows covered by
  the same compiled suite PASS).
- Claude alias: POSIX symlink pass on Darwin/Linux. Windows suite PASS
  (symlink success or fail-closed `unsupported` without copying unmanaged
  files).
- Trailer create/preserve/drift/collision: pass on all four.

SSH used an on-disk identity because the 1Password SSH agent would not sign
for this agent process. Adapter services were observed running on all three
named hosts and were not restarted, re-profiled, or re-enrolled.

## What did not run

- `punaro fleet-config publish` against the owner-managed relay. Production
  PostgreSQL has no `fleet` schema (pre-migration-58). The separate lan-test
  Postgres container crash-looped on start and was stopped again.
- Payload-free wake + HTTP fetch + adapter apply on enrolled clients. Deployed
  adapters are bootstrap-selected binaries from before this feature.
- Offline reconverge, revocation, corrupted-release, and live rollback of a
  desired revision.
- Changing the source repository without publish (no desired-state row exists
  in production).

No production schema migration, adapter profile edit, or new relay was
performed.

## Cleanup

- Remote test binaries were deleted after the run.
- lan-test Postgres left stopped (exited), matching its prior state.

## Residual risk

Live fleet-config publish/converge still requires a schema-59 operator update
and adapter rollout. Until that happens, LAN evidence covers real
filesystem/symlink/apply behavior of the shipped package only. README
reorganization remains blocked until publish/wake/apply can run on the
enrolled clients.
