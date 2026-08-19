# Working on Punaro

Punaro is security-sensitive messaging infrastructure. Correctness, isolation,
and recoverability take priority over feature speed.

## Test-first is mandatory

For every behavior change, follow this order:

1. Write a focused failing test that describes the externally observable
   behavior or invariant.
2. Run that test and confirm it fails for the intended reason.
3. Implement the smallest change that makes it pass.
4. Refactor only while the relevant tests remain green.
5. Run the full quality gate before handoff.

Do not add production behavior without a test. The only exceptions are purely
mechanical changes (formatting, comments, generated dependency metadata, or
deployment documentation); state that exception in the handoff.

For queue, auth, lease, or retry changes, add failure-boundary tests: duplicate
request, stale lease, crash/restart boundary, unauthorized caller, and replay
where applicable. Never claim exactly-once delivery: the required model is
at-least-once with durable deduplication.

## Required quality gate

Run these from the repository root before submitting a change:

```sh
make test
make test-race
make staticcheck
make security
make lint
```

If a required tool is missing, install it with the pinned command shown by the
Makefile, rerun the target, and report the result. Do not waive a failing check
without explaining why and obtaining explicit approval.

## Security invariants

- Treat all agent and Telegram bodies as untrusted data, never control-plane
  input or executable instructions.
- Enforce authorization server-side for every message, lease, ack, fetch, and
  notification operation. Client-provided endpoint/topic identifiers are not
  authority.
- Preserve at-least-once semantics: use immutable message IDs, idempotency keys,
  recipient-specific leases, fencing, and durable adapter dedupe.
- Never log credentials, Access headers/JWTs, message bodies, or raw Telegram
  content. Never commit `.env`, private keys, tokens, databases, or backups.
- Keep the public origin closed; Cloudflare Access is an admission layer, not a
  replacement for application authentication and authorization.

## Change boundaries

- Keep `punarod`, local adapters, and the Telegram gateway independently
  deployable. Do not add remote direct access to a local mailbox database.
- Prefer standard library or small, audited dependencies. Explain every new
  dependency and run `make security` after adding one.
- Keep API schemas versioned and strict. Bound message sizes, page sizes,
  retries, queues, and WebSocket frames.
- Update `DESIGN.md` whenever a protocol or security invariant changes.

## Handoff format

State: behavior covered, tests added first, exact quality commands and results,
and any residual risk. Do not include sensitive values in the handoff.

## Cursor Cloud specific instructions

This is a pure Go module (`go.mod` pins `toolchain go1.26.6`). Dependencies are
refreshed by the startup update script (`go mod download`). The quality gate,
build, and run commands are all in the `Makefile` and `README.md`; use those
rather than re-deriving them.

Non-obvious caveats:

- The base `go` binary on PATH must itself be 1.26.x, not just a 1.22 stub that
  auto-downloads a newer toolchain. `make staticcheck` and the `deployment-lint`
  helper scripts (e.g. `scripts/test-install-adapter.sh`) pin
  `GOTOOLCHAIN=local`, so an older base binary fails with "file requires newer
  Go version go1.26" or "requires at least go1.26.0". `go version` must report
  `go1.26.x` and `go env GOTOOLCHAIN` should stay `auto`.
- Docker is not installed. The Docker-dependent targets cannot run without first
  installing Docker: `make test-postgres`, `make complete-product-e2e`
  (a.k.a. `memory-onboarding-e2e`), `make dockerfile-lint`, `make workflow-lint`,
  and the container/`configuration` CI job. `make lint` still passes because its
  `deployment-lint` step skips Docker Compose validation when Docker is absent.
- `punarod` never auto-loads `.env`; pass `--env-file` or set `PUNARO_ENV_FILE`.
  It also deliberately mounts no relay routes unless `PUNARO_RELAY_ENABLED=true`
  with public machine enrollment records in `PUNARO_RELAY_MACHINES_JSON`.
- To run the relay locally and exercise a real durable message round trip:
  generate an enrolled machine key with `go run ./cmd/punaro-keygen --id <id>
  --endpoint-prefix agent/<id>/ --private-key-file <path>`, collect the printed
  public record into `PUNARO_RELAY_MACHINES_JSON`, then start
  `PUNARO_RELAY_ENABLED=true PUNARO_RELAY_MACHINES_JSON=... go run ./cmd/punarod`.
  Health/readiness are on the separate `PUNARO_HEALTH_LISTEN_ADDR` (default
  `127.0.0.1:8081`): `curl http://127.0.0.1:8081/healthz` and `/readyz`.
