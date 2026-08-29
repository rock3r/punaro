# Fleet-config LAN qualification

This opt-in runbook qualifies fleet-global agent configuration against the
owner-managed LAN used by [`durable-role-lan-e2e.md`](durable-role-lan-e2e.md):
`mac-studio`, `coso`, and `mattone`. It does not provision a relay, invent
credentials, or change adapter profiles. Replace every all-caps placeholder
locally. Never record secrets, relay URLs, Access headers, machine keys, DSNs,
mailbox bodies, `AGENTS.md` contents, skill contents, or production identifiers.

A passing personal record belongs under [`deployment-validation`](deployment-validation/).
It does not check boxes in [`security-release-gates.md`](security-release-gates.md)
or write official [`release-evidence`](release-evidence/).

If any host is unreachable, or a real symlink/ACL/junction check cannot run,
stop and record the host as unverified. Do not substitute unit-test path
simulation.

## Preconditions

From the candidate checkout:

```sh
for host in mac-studio coso mattone; do
  ssh "$host" 'hostname; uname -s; git -C PATH_TO_PUNARO rev-parse HEAD; git -C PATH_TO_PUNARO status --porcelain'
done
```

Confirm `punarod` and adapters are healthy. Use the existing owner-managed
installation directory as `INSTALL_DIR`. Configure the source repository with
`punaro fleet-config configure --directory INSTALL_DIR --repository ABSOLUTE_GIT_DIR --yes`.

## Minimum scenarios

1. Publish an exact commit that contains global `AGENTS.md`/`skills/` plus at
   least two project trees. Confirm preview lists source commit, release digest,
   skill count, total bytes, and current desired revision, then confirm with
   `--yes --confirm-preview-hash`.
2. Confirm a payload-free wake plus HTTP fetch and atomic apply on all three
   enrolled clients.
3. Confirm project-only files apply only for top-level matches under the
   configured base path, and that one explicit per-machine override works.
4. Confirm a machine-local `AGENTS.md` trailer survives publish, reconverge,
   and rollback.
5. Confirm Claude alias opt-in on at least one POSIX host and the Windows
   equivalent, or an explicit unsupported failure without copying.
6. Offline client converges after reconnect; revoked client cannot fetch or
   report.
7. Invalid publication, corrupted release, interrupted apply, fleet-prefix
   drift, unsupported harness, and rollback of a bad desired release.
8. Changing the source repository without `fleet-config publish` causes no
   fleet change.
9. `punaro fleet-config status` and doctor show bounded states without
   configuration contents.

## Record

Write only candidate commit, host role, redacted commands, pass/fail, cleanup,
and residual risk. Use native PowerShell on `mattone`.
