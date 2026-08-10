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

- Integrated source commit: `8d7b7f7670cc10484a493f4003156e0be0673c05`.
- Relay artifact-producing commit:
  `8d7b7f7670cc10484a493f4003156e0be0673c05`.
- Adapter artifact-producing commit:
  `ba633f0d20a5e3c0b0711b2893521c9f59a2530e`. The final review fix changes
  only PostgreSQL legacy-key resolution in the relay; rebuilding both adapter
  platforms from the integrated source reproduced their exact deployed hashes.
- Review reference: PR #131, branch
  `agent/issue-55-durable-role-e2e`.
- Signed/tagged release reference: none; official release remains withheld.
- Linux/amd64, `CGO_ENABLED=0`, `punarod` SHA-256:
  `be0e237866ae40ff5d72a2bbe6162443c1e3a9b7a0d7893f6933a704724f660a`.
- macOS/arm64 native-CGO `punaro-adapter` SHA-256, deployed independently on
  Mac Studio and Coso:
  `3dc6747db9f9edce98ef566ab8ab045c905a18fc334a7735c08c28eb16be4059`.
- Windows/amd64, `CGO_ENABLED=0`, `punaro-adapter.exe` SHA-256:
  `35e3132a84c40ff69f2aa360e6667b7c19f95d8a218db5677abccc93bb45f870`.
- Container image digest: not applicable; the validated relay is the native
  systemd deployment.

All four installed artifacts were hashed after the final scenario and matched
the values above. The relay was built from the final review-fix commit; both
adapter artifacts were rebuilt from that commit and reproduced their earlier
deployed hashes exactly.

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
real two-client relay lifecycle E2E. The final integrated-head run's latter
test passed in 83.198 seconds. The Docker-backed PostgreSQL integration suite
also passed in 29.610 seconds after first demonstrating that the new
closed-gate registration test failed for the intended reason.

GitHub Actions candidate run: pending final evidence-only synchronization.
The earlier complete role-routing candidate run is retained at
`https://github.com/rock3r/punaro/actions/runs/31419646148`; it does not replace
the final candidate run.

## Deployment admission and enrollment

- The relay, Mac Studio, Coso, and Mattone ran the exact candidate binaries.
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

- Six pairwise host directions completed. Every intended endpoint observed
  each opaque probe once and acknowledged it. A same-key retry returned the
  original message identity and caused no duplicate mailbox injection.
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
- Mattone replacement `w3 -> w4`: the same generation `1 -> 2`, stale-ack
  `403`, replacement-ack `204`, and detached stale-bind `403` proof passed
  using native Windows process and scheduled-task lifecycle.
- Offline recovery: Coso was stopped through launchd, a targeted message was
  accepted while unavailable, then the restored adapter committed and
  acknowledged it on polling attempt 9. A later receive observed zero
  duplicates.
- Attachment fail-closed boundary: the running relay had zero trusted or
  retired attachment environment keys. Signed trusted-attachment, v2
  directory, and v3 permit routes each returned `404` without creating state.
- Remote memory fail-closed boundary: the running relay had zero memory or
  remote-MCP environment keys. Signed memory and MCP routes returned `404`.
  A functional memory E2E was therefore intentionally unavailable; no mock or
  offline substitute was counted.
- After deploying the final review-fix relay hash, a fresh targeted-role probe
  reached Coso's bound primary session exactly once and its endpoint plus other
  role session zero times. The delivery was acknowledged; a same-key retry
  returned the same message identity and produced zero duplicate mailbox
  injection. Four distinct signed machine identities also renewed six active
  endpoint leases through the final relay.

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
- Owner-managed adapter rollback copies with suffix `.pre-ba633f0` and the
  final relay rollback copy `.pre-8d7b7f7` were retained beside their installed
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
