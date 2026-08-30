# Fleet-config personal-deployment validation — 2026-08-29

## Decision and scope

- Capability: fleet-global agent configuration from issues #210–#217 plus the
  three operator additions (project-only trees, machine-local trailers, opt-in
  Claude aliases).
- Personal deployment result: **pass for live apply and remaining gating on
  the named three hosts plus Linux**, with Darwin HTTP reaching the LAN origin
  through a loopback forwarder (see Darwin HTTP).
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
| `coso` (adapter) | Darwin arm64 | SSH | PASS | PASS (threaded loopback forwarder + path override) |
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
`--yes --confirm-preview-hash`). Preview listed source commit, release digest,
skill count, total bytes, and current desired revision. Generation 2
republish reconverged Linux with a surviving machine-local trailer body.

Shipped `punaro-adapter` then fetched desired metadata and the
digest-addressed archive and applied it:

- Linux LXC: direct LAN HTTP; POSIX `CLAUDE.md` symlink; status `current`.
- `mac-studio` and `coso`: same shipped Darwin adapter. Direct Go HTTP to
  the LAN listen address completes TCP but never sends request payload
  (tcpdump: handshake only; server `ReadHeaderTimeout` FIN). `curl` and
  Apple-signed Python GET the same URL and receive `401`. A loopback
  forwarder (SSH `-L` on mac-studio; Apple-signed threaded Python on `coso`)
  lets the adapter speak HTTP on `127.0.0.1` while still applying on the host
  filesystem. `coso` used an explicit project path override; an unmatched
  top-level name was not written.
- `mattone`: direct LAN HTTP after an exclusive current-user DACL on the
  sandbox profile. Native `CLAUDE.md` symlink to `AGENTS.md` (reparse point).
  Status PUT returned 403 because that sandbox machine had no
  `auth.client_installations` row; apply still occurred. `coso` has the same
  PUT 403 for the same reason.

### Darwin HTTP

Root cause is macOS 26 Local Network filtering of ad-hoc-signed Go
binaries: SYN/ACK succeeds, `Write` returns success, no PSH appears on
the LAN interface. Not a Punaro request-signing bug. Loopback to the
same `punarod` (SSH `-L` or Python forwarder) returns normally. A
single-connection Python forwarder stalls HTTP while a WebSocket is
held; multiplexing (SSH `-L` or a threaded forwarder) is required.

### Filesystem suite (named hosts, earlier the same day)

On each named host, the compiled `internal/fleetconfig` test binary from
`agent/fleet-config-217` passed atomic apply, last-known-good, trailer, and
Claude-alias behavior.

SSH used an on-disk identity because the 1Password SSH agent would not sign
for this agent process. Production adapter profiles were not edited.

### Remaining gating (named hosts)

Scenarios below used the same lan-test origin and sandbox apply roots. Fixture
source commits and release digests are recorded; configuration contents are
not.

1. **Publish preview + confirm.** Exact-commit publish printed content-free
   preview (source commit, release digest, skill count, total bytes, current
   desired generation/digest) then required `--yes --confirm-preview-hash`.
2. **Payload-free wake + HTTP apply.** A signed WebSocket subscriber captured
   `{"type":"wake","topic_id":"fleet-config","sequence":3}` with three JSON
   keys and no extra fields (no digest, commit, path, or contents). mac-studio
   then applied generation 3 (`94d8a17b…`). `coso` and `mattone` applied the
   same digest on disk after the multiplexed forwarder / live adapter were
   running.
3. **Project-only match.** `coso` has a top-level `punaro` match and an
   unmatched `other` directory; project `AGENTS.md` was written only for the
   match. `canopi` was written on mac-studio and mattone where that top-level
   directory existed.
4. **Trailer survival.** A machine-local trailer token seeded before later
   publishes survived v3 apply, offline reconverge, corrupt/interrupt
   recovery, and rollback to the previously published v2 digest
   (`de205931…`, generation 7).
5. **Claude aliases.** POSIX `CLAUDE.md` symlink on mac-studio and coso;
   Windows reparse-point symlink on mattone. No content copy.
6. **Offline reconverge.** mac-studio sandbox adapter stopped; generation 4
   published (`7d84126e…`); on-disk digest stayed at generation 3; operator
   status kept the stale client generation; adapter restart applied generation
   4 and reported `current`.
7. **Revoke.** Extra Linux machine `fleet-lan-lxc` fetched desired (HTTP 200)
   while enrolled. After removing it from lan-test `RELAY_MACHINES_JSON` and
   restarting only the lan-test `punarod`, the same key received HTTP 401 on
   desired fetch. mac-studio still fetched HTTP 200. Named-host machines were
   not revoked.
8. **Invalid publication.** An extra top-level `README.md` commit refused
   materialize (`preview_rc=1`); desired generation/digest unchanged; source
   HEAD restored to the previously published commit.
9. **Corrupt release.** A keepalive-aware loopback proxy truncated
   `GET /v1/fleet-config/releases/…` bodies. Adapter log:
   `fleet-config archive is invalid`. Applied digest stayed on last-known-good
   (`4b5b28cc…`). Restoring the uncorrupted path applied generation 6
   (`2327bd0b…`).
10. **Interrupted apply.** `chflags uchg` on the live tree produced
    `fleet-config last-known-good failed`; applied.json was not advanced.
    Clearing the flag reconverged. Trailer token remained.
11. **Fleet-prefix drift.** A local prefix edit in the managed `AGENTS.md`
    was replaced (not merged) on the next desired-generation apply; trailer
    token remained.
12. **Unsupported harness marker.** A `.cursor` directory was created in the
    sandbox home. Live apply does not fail closed on that vendor dir;
    `DetectHarnesses` unit tests cover the `unsupported` report.
13. **Rollback.** `fleet-config publish` of previously stored source commit
    `f9415d9d…` set desired generation 7 / digest `de205931…`. mac-studio
    applied it and reported `current`. Trailer token remained.
14. **Unpublished source change.** Dirty working-tree edit of the configured
    source `AGENTS.md` left desired generation 2 / digest `de205931…`
    unchanged; the edit was reverted without publish.
15. **Status/doctor.** `punaro fleet-config status` returned bounded fields
    only (source commit, digest, generation, skill/byte counts, client
    machine id + state enum + trailer/alias states). No configuration
    contents, host paths, or raw errors.

## What did not run

- Direct (unproxied) Darwin Go HTTP to the LAN listen address. Documented
  above; apply used a loopback forwarder.
- `mattone` and `coso` content-free status rows (PUT 403 without an
  enrollment installation). Apply and alias were still observed on disk.
- Production schema migration, production adapter profile edit, or a new
  Internet-facing relay.

## Cleanup

- Sandbox adapters on mac-studio, coso, and mattone were left for operator
  follow-up or stopped after the run; production adapters were not edited.
- lan-test Postgres on 15432 and the candidate lan-test `punarod` were left
  running for further operator use; production listeners were unchanged.
- Fixture source, keys, and enrollment material remain host-local and are not
  in git. A lan-test extra machine was removed from the sandbox machines JSON
  as the revoke scenario; named-host entries remain.

## Residual risk

Darwin live fetch depends on a multiplexed loopback forwarder until adapters
are code-signed for Local Network. Status PUT requires
`auth.client_installations`; JSON-only machines apply but cannot report.
Official security-release-gate boxes stay unchecked. Production was not
migrated.

## Contract-fix retry (2026-08-30)

Candidate: `agent/fleet-config-adapter-http` `66e269c` (last-known-good only
after live is displaced; harness/alias apply; doctor/Canopi fleet checks;
stale client reports expire to `offline`). lan-test `punarod` and the three
named-host adapters were rebuilt from that commit. Production listeners on
`127.0.0.1:8080` / `127.0.0.1:5432` stayed untouched; lan-test remained on
`192.168.1.254:8080`, health `127.0.0.1:18081`, Postgres `127.0.0.1:15432`,
schema 59.

| Host | Live apply after `66e269c` |
| --- | --- |
| `mac-studio` | PASS via SSH `-L` loopback; operator status `current` |
| `coso` | PASS via threaded loopback forwarder + path override; PUT 403 |
| `mattone` | PASS direct LAN HTTP; `CLAUDE.md` reparse point; PUT 403 |

Post-contract publish of exact source `0870c8b2…` became desired generation
10, digest `688048f6…`. Signed WebSocket capture:
`{"type":"wake","topic_id":"fleet-config","sequence":10}` with three JSON
keys and `extra_keys=0`. All three named hosts applied that digest; machine-local
trailer token survived; unmatched `other` was not written; `coso` wrote
`canopi` only at the override path.

A later exact-commit publish (`114f4677…`, generation 11, digest `db856b83…`)
was used for last-known-good. With a keepalive-aware truncating proxy in
front of the mac-studio loopback, the adapter logged
`fleet-config archive is invalid` and kept last-good `688048f6…`. Restoring
the uncorrupted path applied `db856b83…`; trailer token remained. `coso` and
`mattone` applied generation 11 directly.

Unpublished working-tree edit left desired generation 10 unchanged. Extra
top-level `README.md` refused materialize (`preview_rc=1`); desired
unchanged. After the new `punarod`, operator status showed
`fleet-lan-lxc` as `offline` (stale report expired) and
`fleet-lan-mac-studio` `current` at generation 11. `punaro doctor` emitted
content-free `fleet_config_desired` pass and `fleet_config_client_stale` fail
for that offline row; no configuration contents. A `.cursor` directory in
the mac-studio sandbox home did not block apply.

README split remains the earlier `722c3ac` relocation; this retry did not
re-duplicate operator/runbook detail into `README.md`. Security-release-gate
boxes stay unchecked. Same Darwin HTTP and JSON-only PUT residuals as above.
