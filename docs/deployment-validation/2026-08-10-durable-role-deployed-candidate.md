# Durable-role personal-deployment validation — 2026-08-10

## Decision and scope

- Capability: durable conversation roles, session replacement fencing, and
  targeted role delivery from issues #55 and #58.
- Personal deployment result: **validated** for the owner-managed Punaro
  deployment described in the installation guide. This is operational test
  evidence, not release-gate approval or official release evidence.
- Official Internet-facing release decision: **withheld**. This record does
  not check any box in
  [`security-release-gates.md`](../security-release-gates.md); no signed
  release tag, independent human approvals, SBOM, or artifact attestation was
  produced for this personal release candidate.
- Operator and security reviewer: Seb, acting as the owner-operator permitted
  by the personal self-hosted-build rule. Cryptography approval is not
  applicable because this change does not add or alter a cryptographic
  protocol.

## Exact candidate

- Integrated source commit: `ef34cc74f9ff28ea1b98564b4e8078c9545527f8`.
- Relay artifact-producing commit:
  `d58a9f75267172c2ddb1ce645531f507899ac186`.
- Adapter artifact-producing commit:
  `d58a9f75267172c2ddb1ce645531f507899ac186`.
- The integrated commit changes deployment documentation only; its executable
  source tree is identical to the artifact-producing commit.
- Review reference: PR #131, branch
  `agent/issue-55-durable-role-e2e`.
- Signed/tagged release reference: none; official release remains withheld.
- Linux/amd64, `CGO_ENABLED=0`, `punarod` SHA-256:
  `3f8ed32b929ec14a19b3c3c4c6b636fea8987486a7c89f94929ca76bd4b5e678`.
- macOS/arm64 native-CGO `punaro-adapter` SHA-256, deployed independently on
  Mac Studio and Coso:
  `df668fc9c0546f5bdda81461548d2426da1d5ef3bc0c4fbcde6d09fbc84f9a9a`.
- Windows/amd64, `CGO_ENABLED=0`, `punaro-adapter.exe` SHA-256:
  `134311ecc55134d5eaca47b973df1d7ec7c61b444f75405f68c042339edd5969`.
- Container image digest: not applicable; the validated relay is the native
  systemd deployment.

All four installed artifacts were hashed after the final scenario and matched
the values above. The relay and native adapter artifacts were built from the
same executable commit; the integrated head adds only this deployment record
and deployment-guide corrections.

## Verification gates

The following command passed from a clean protected-path worktree at the
integrated source commit:

```sh
env GOCACHE=/tmp/punaro-go-cache \
  make test test-race staticcheck security lint test-real-relay-e2e
```

Results included unit coverage, race tests, Staticcheck, `govulncheck` with no
called vulnerabilities, `gosec` with zero issues, Gitleaks with no leaks, Go
vet, lint, Windows compilation, deployment and installer verification, and the
real two-client relay lifecycle E2E. The final executable-head run's latter
test passed in 81.876 seconds. The Docker-backed PostgreSQL integration suite
passed in 26.721 seconds and the command integration suite in 3.996 seconds
after first demonstrating the skipped-recipient cursor failure against the
pre-fix implementation.

GitHub Actions candidate run:
`https://github.com/rock3r/punaro/actions/runs/31442527469`. Configuration lint,
Go tests and analysis, PostgreSQL integration, Windows build, complete-product
E2E, and Cursor Bugbot all passed at the final deployed review head.

## Deployment admission and enrollment

- The relay, Mac Studio, Coso, and Mattone ran the exact artifact-producing
  candidate binaries while the integrated head differed only in documentation.
- The relay is the historical native systemd/SQLite deployment. Its configured
  health listener is `127.0.0.1:18081`; checking an assumed port caused an
  unnecessary intermediate rollback. The final replacement used the configured
  endpoint and required no PostgreSQL migration.
- All machine credentials retained their narrow endpoint namespaces. Missing
  Mac Studio and Coso validation prefixes were added additively; no existing
  enrollment was removed or widened.
- Cloudflare Access used a Service Auth (`non_identity`) policy naming three
  distinct exact per-machine service tokens. No
  `any_valid_service_token` rule was used.
- Header-authenticated unsigned `/v1/conversations` probes reached Punaro and
  returned application JSON `401` without redirects on all three adapter
  machines.
- A live regression proved Cloudflare accepted a signed request carrying only
  the service-token headers and rejected the same request when a browser
  `CF_Authorization` cookie was mixed in. The final adapter never establishes
  or replays that cookie with Service Auth credentials.
- The final relay review fix permits only an owner-registered pending key under
  an active mail cutover while the migration-wide legacy gate remains closed;
  the integration proof confirmed that an earlier migrated key stays rejected.

## Redacted live outcomes

All probes used disposable aliases, roles, conversation state, opaque bodies,
and idempotency keys. No credential, header value, private key, conversation
identifier, delivery identifier, lease token, or body was recorded here.

- Six pairwise host directions completed again on the final artifact. Every
  intended endpoint observed each opaque probe once and acknowledged it. A
  same-key retry returned the original message identity and caused no duplicate
  mailbox injection.
- Targeted role delivery reached only Coso's bound primary session. Its local
  endpoint, other Coso role, replacement session, Mac Studio, and every
  Mattone session received zero copies.
- An untargeted broadcast remained compatible: Coso's endpoint plus two bound
  roles received and acknowledged three copies total; Mattone's endpoint plus
  two bound roles did the same. Unbound replacement sessions and the sending
  endpoint received zero copies.
- Coso replacement `c3 -> c4`: the old session leased generation 1; rebinding
  invalidated its acknowledgement with HTTP `403`; the replacement reclaimed
  the same delivery at generation 2 and acknowledged with `204`. After normal
  detachment, stale bind also returned `403`.
- Mattone replacement `w3 -> w4`: generation `2 -> 3`, stale-ack
  `403`, replacement-ack `204`, and detached stale-bind `403` proof passed
  using native Windows process and scheduled-task lifecycle.
- Offline recovery: Coso was stopped through launchd and a targeted message was
  accepted while unavailable. The restarted adapter was correctly fenced with
  `409` until the stopped process's consumer lease expired, then injected one
  authenticated-role delivery, acknowledged it, and produced zero duplicates.
- Attachment fail-closed boundary was rechecked on the final relay: its process
  had zero trusted or retired attachment environment keys. Signed
  trusted-attachment, v2 directory, and v3 permit routes each returned `404`
  without creating state.
- Remote memory fail-closed boundary was rechecked on the final relay: its
  process had zero memory or remote-MCP environment keys. Signed memory and MCP
  routes returned `404`.
  A functional memory E2E was therefore intentionally unavailable; no mock or
  offline substitute was counted.
- The final Coso and Mattone replacement proofs both carried the exact
  server-derived `recipient_role`. Two local acknowledgements were recovered
  from agent-mailbox's durable leased state after a deliberately malformed
  test command, exercising at-least-once handling without duplicate injection
  and without displaying lease tokens or message bodies.

## Cleanup, health, and rollback

- The supported conversation control plane removed both disposable non-admin
  endpoint members and recorded two audit events.
- Each original attached group was restored. A final audit found stale
  disposable memberships in the real attached groups; the Mac Studio and Coso
  aliases plus one Mattone alias were removed. Active disposable aliases were
  then zero on all three machines.
- Punaro currently exposes no supported conversation-delete or role-member
  removal operation. The isolated conversation's final admin and durable role
  metadata therefore remain as the only residual test state; deleting relay
  storage directly was rejected as unsafe and outside the supported control
  plane.
- Final health: relay `active` and ready; both macOS launchd adapters running;
  Mattone scheduled task hidden and running a hidden-window action with
  exactly one process at the candidate path.
- Owner-managed adapter rollback copies of the preceding `439cb27` binaries
  and the relay rollback copy of `8e8eeb8` were retained beside their installed
  binaries. Rollback requires the documented service stop, atomic binary
  replacement, restart, hash check, and readiness check. This evidence expires
  when any listed artifact is replaced or the Access policy/enrollment
  authority changes.

## Security-gate disposition

- [`Trusted-relay attachments`](../security-release-gates.md#trusted-relay-attachments-gated-candidate-closed):
  unchanged and closed.
- [`Attachment v2`](../security-release-gates.md#attachment-v2-superseded-closed)
  and
  [`Attachment v3`](../security-release-gates.md#attachment-v3-controlled-runtime-superseded-not-released):
  unchanged, retired, and closed.
- [`Public relay and operations`](../security-release-gates.md#public-relay-and-operations-closed):
  unchanged and closed for an official release. The owner-managed personal
  deployment evidence above is not independent release approval.
