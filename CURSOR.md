# Cursor Cloud

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
- To bring up a local loopback relay for Cloud smoke checks: generate an
  enrolled machine key with `go run ./cmd/punaro-keygen --id <id>
  --endpoint-prefix agent/<id>/ --private-key-file <path>`. Keygen prints one
  enrollment object; capture it and wrap it in a JSON array with shell-safe
  quoting before starting the relay (a bare object fails with
  `parse machine enrollment: expected array`; nesting the object inside
  `"[{...}]"` also breaks JSON quotes in the shell):

  ```sh
  record="$(go run ./cmd/punaro-keygen --id <id> --endpoint-prefix agent/<id>/ --private-key-file <path>)"
  PUNARO_RELAY_ENABLED=true PUNARO_RELAY_MACHINES_JSON="[$record]" go run ./cmd/punarod
  ```

  Health/readiness are on the separate `PUNARO_HEALTH_LISTEN_ADDR` (default
  `127.0.0.1:8081`): `curl http://127.0.0.1:8081/healthz` and `/readyz`. Those
  probes only prove daemon startup, not durable delivery.
- For a real durable round trip (create conversation → advertise → send →
  lease → ack, including unauthorized-lease and retry boundaries), use the
  maintained gate rather than hand-rolling signed client calls here: on a
  disposable macOS GUI login with `agent-mailbox` on `PATH`, run
  `make test-real-relay-e2e`, and follow
  [`docs/alpha-text-relay.md`](docs/alpha-text-relay.md) for operator/adapter
  command sequences. That target LookPaths the legacy `agent-mailbox` binary
  name (a PATH with only `waypost` is not enough for this smoke test).
