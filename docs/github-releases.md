# GitHub Releases origin

Punaro's public artifact origin is GitHub Releases. This is the fixed source
`punaro-bootstrap` pulls from. The gateway may name a signed release; it
never supplies a download URL, installer script, or unsigned `latest` pointer.

This is the release-trust slice of
[`client-lifecycle-compatibility-recovery-rfc.md`](client-lifecycle-compatibility-recovery-rfc.md).
The workflow produces a draft unsigned candidate; when a live catalog exists,
the replacement candidate retains every prior release still eligible for
rollback. An operator publishes it only after the offline signatures and release evidence are attached. Enrollment
and host-local update recovery remain separate from release publication.

## Fixed origin

```text
https://github.com/rock3r/punaro/releases/download
```

Relative paths beneath that origin are the only names bootstrap may request.
GitHub Release assets are flat; the tag is the first path component.

| Path | Meaning |
| --- | --- |
| `catalog/punaro-catalog.json` | Short-lived catalog of currently allowed releases |
| `catalog/punaro-catalog.sig` | Detached Ed25519 envelope for the catalog |
| `{release}/punaro-release.json` | Immutable manifest for one named release |
| `{release}/punaro-release.sig` | Detached Ed25519 envelope for that manifest |
| `{release}/{component}-{os}-{arch}[.exe]` | Native artifact |

`latest` is a reserved name and is rejected by the parser. There is no
mutable latest pointer.

A bootstrap honors a gateway-selected release only when a fresh verified
catalog lists that exact release name, sequence, and manifest digest, and does
not critically block it. A signed manifest proves artifact identity; the
catalog proves the release is still allowed for an automatic update.

## macOS signing test

The `macos-notarize` workflow is `workflow_dispatch` only. It builds
`darwin/arm64` with CGO, imports the Developer ID Application certificate,
signs each binary under `dev.sebastiano.punaro.<component>`, wraps them in a
UDZO DMG (the only staple-able container we ship today), notarizes with the
Apple ID + app-specific password, and staples the ticket. It uploads the DMG
as a workflow artifact and does not create a GitHub Release.

```sh
gh workflow run macos-notarize.yml --repo rock3r/punaro --ref <branch>
```

## What CI publishes

The `release` workflow first validates every dispatch identity and policy input
and proves the named GitHub Release does not already exist. Only after that
read-only preflight passes does it publish the Linux/amd64 gateway image to GHCR
with OCI SBOM and provenance attestations, capture its registry digest, and bind
that exact `ghcr.io/rock3r/punaro@sha256:...` identity into the release manifest
and native build provenance. Invalid or reused release requests therefore
cannot create or move an official image tag. The image carries the release name
as `org.opencontainers.image.version`; its pre-digest operator binary is bound
to the release-tagged GHCR repository identity known at build time and requires
a digest-pinned installation from that repository. It then builds:

- `punaro-adapter`, `punaro-trusted-attachment`, `punaro-memory`,
  `punaro-enroll`, and `punaro-bootstrap` for `darwin/arm64`, `linux/amd64`,
  `linux/arm64`, and `windows/amd64`
- `punaro`, `punaro-telegram`, and `punaro-relay-adopt-prepare` for Linux

Darwin adapter builds use `CGO_ENABLED=1` so the supported ACL path is compiled
in. The workflow then writes unsigned `punaro-release.json` and
`punaro-catalog.json` and creates a **draft** GitHub Release. The private
release key is not a CI secret and is never placed in this repository.

Unsigned draft bytes are a publication candidate. Bootstrap must fail closed
until both detached signatures are present and verify against a public key
embedded in that bootstrap.

The offline publisher re-hashes every native artifact named by the verified
manifest in the operator's signing directory and in the GitHub draft before it
publishes anything. It repeats remote artifact verification after publication;
a mismatch prevents catalog advancement or restores/hides the previous catalog
state. Replacing an existing catalog first makes that GitHub Release a draft,
uploads the document/signature pair while it is unavailable to bootstrap
clients, downloads and verifies the remote bytes, and only then exposes the
release again. A failure restores the previously verified pair while the
catalog remains hidden. The signing directory must therefore retain the exact
native artifacts alongside the four signed document files.

The unsigned workflow never creates or mutates the live `catalog` prerelease.
Only the offline-signature publisher can make those stable assets visible.

## Cutting a candidate

1. Merge the commit you intend to ship.
2. Run the `release` workflow with an explicit release name and sequence. Do
   not publish by pushing a tag; the workflow is dispatch-only so the sequence
   cannot race a live repo variable. Overlapping dispatch runs queue.

   ```sh
   gh workflow run release.yml --repo rock3r/punaro --ref main \
     -f release=v0.1.0-alpha.1 \
     -f sequence=1 \
     -f catalog_sequence=1 \
     -f minimum_bootstrap_release=v0.1.0-alpha.1
   ```

   `minimum_bootstrap_release` is the oldest fixed, installer-owned bootstrap
   executable that can safely supervise the target release. Keep it at
   `v0.1.0-alpha.1` for alpha.2 unless the bootstrap protocol actually becomes
   incompatible; signed slot updates do not replace that fixed executable.
   Later dispatches may set `minimum_safe_sequence` to retire every lower
   sequence, and `critical_blocks` to a comma-separated list of individual
   unsafe sequences. The workflow validates both before assembly. Use the
   safety floor only when every older rollback is intentionally retired; use a
   critical block to revoke one release while keeping older safe rollback
   entries. A critical block must name an older sequence, never the current
   release being published; blocks below a raised safety floor are retired.
   Set `supported_from` to the comma-separated installed releases that
   may upgrade directly to this release; this is required for rolling fleet
   transitions after the first release.
3. Wait for the draft release to appear. The live `catalog` prerelease is not
   touched by the unsigned workflow.
4. Generate the offline key once, on an air-gapped or owner-only machine, and
   keep the private file `0600` off this repository:

   ```sh
   go run ./cmd/punaro-release keygen \
     --key-id punaro-release-1 \
     --private-key-file /absolute/private/punaro-release.key \
     --public-key-file /absolute/private/punaro-release.pub
   ```

5. Sign the exact published bytes (download them; do not re-encode JSON):

   ```sh
   go run ./cmd/punaro-release sign \
     --key-id punaro-release-1 \
     --key-file /absolute/private/punaro-release.key \
     --in punaro-release.json \
     --out punaro-release.sig
   go run ./cmd/punaro-release sign \
     --key-id punaro-release-1 \
     --key-file /absolute/private/punaro-release.key \
     --in punaro-catalog.json \
     --out punaro-catalog.sig
   go run ./cmd/punaro-release verify \
     --keys-file /absolute/private/punaro-release.pub \
     --document punaro-release.json \
     --signature punaro-release.sig
   ```

6. Put the downloaded manifest/catalog and both offline signatures in one
   private directory. Publish only after the tool re-verifies both signatures
   and proves the draft contains the exact signed bytes:

   ```sh
   ./scripts/publish-signed-release.sh \
     --release v0.1.0-alpha.1 \
     --dir /absolute/private/signed-alpha.1 \
     --keys-file /absolute/private/punaro-release.pub
   ```

   The publisher rejects a catalog outside its signed lifetime and requires a
   candidate sequence strictly above the verified live catalog before changing
   either release. It also rejects a replacement that drops an eligible live
   release, lowers the safety floor, or removes a critical block. It makes the
   immutable versioned prerelease available first.
   Initial live-catalog publication stays draft until both signed assets are
   uploaded. On replacement, the publisher first downloads and verifies the
   existing pair and uploads that signed predecessor under reserved recovery
   asset names before hiding the live catalog. It retains those recovery assets
   across successful publication, remotely re-downloads and verifies the new
   pair, and restores the previous pair (with bounded retries) after any partial
   upload, signal, or verification failure. A later invocation that encounters
   an interrupted replacement draft must verify and sequence against that
   retained predecessor; it cannot treat the draft as history-free. If a
   failure happens after the versioned prerelease is visible, rerunning the
   helper is safe: it accepts
   only that exact retryable prerelease and rechecks all signed bytes before
   advancing the catalog. A first or previously interrupted draft catalog is
   returned to draft state after any failed exposure or remote verification,
   so bootstrap never relies on that unverified pair. The unsigned build
   workflow never touches the live catalog. Pass the public key set to
   `punaro-bootstrap update --keys-file`. Do not embed a production key until
   the first official signed release exists.
7. An official maintained release still requires the
   [security release gates](security-release-gates.md) and a
   [release-evidence record](release-evidence/README.md). This origin does not
   bypass those gates.

## Local assembly

```sh
./scripts/build-release-artifacts.sh \
  --output-dir ./dist \
  --release v0.1.0-alpha.1 \
  --sequence 1 \
  --catalog-sequence 1 \
  --image ghcr.io/rock3r/punaro@sha256:IMAGE_DIGEST
go run ./cmd/punaro-release assemble \
  --dir ./dist \
  --release v0.1.0-alpha.1 \
  --sequence 1 \
  --catalog-sequence 1 \
  --minimum-bootstrap-release v0.1.0-alpha.1 \
  --image ghcr.io/rock3r/punaro@sha256:IMAGE_DIGEST
go run ./cmd/punaro-release validate --dir ./dist
```

For every release after the first, pass the verified live catalog with
`--previous-catalog ./punaro-catalog.json`. The assembler retains its eligible
rollback entries and safety floor; releases leave the replacement only through
an explicit higher `--minimum-safe-sequence` or repeatable `--critical-block
SEQUENCE`. Declare every direct rolling-upgrade source with repeatable
`--supported-from RELEASE`; the workflow accepts the same set through its
comma-separated `supported_from` input. The GitHub
workflow downloads the live catalog and supplies this argument automatically.
Before dispatching the second or any later release, configure the repository
Actions variable `PUNARO_RELEASE_PUBLIC_KEYS` with the exact JSON contents of
the independently distributed `punaro-release.pub` trust root. If a published
live catalog exists, the workflow downloads both `punaro-catalog.json` and
`punaro-catalog.sig` and fails closed unless that pair verifies against the
configured trust root. The first release does not require this variable because
there is no inherited live catalog. The offline publisher separately verifies
the signed replacement against the independently verified live pair before
mutation.

`assemble` hashes the exact generated `compose.operator.yaml` template installed
by `punaro init` and staged by `punaro update`, plus the embedded migration
manifest. Published releases require the workflow-produced digest-pinned GHCR
image; it must be `@sha256:` and `release_sha256` must match. The separate
`deploy/compose/production.yaml` file remains the reference single-node bundle;
it is not the host-local operator artifact checked during update and doctor.

## Bootstrap pull

`punaro-bootstrap` fetches only two-component paths beneath the fixed origin,
verifies the catalog and manifest signatures, checks exact length/digest, and
publishes `current` / `previous` slots. Platform services launch
`punaro-bootstrap run`, which starts the current-slot adapter with the
existing host-local profile. After a previous slot exists, the new current
must write a content-free ready file within 60 seconds; otherwise run rolls
back once when the fresh catalog still lists that previous release, or enters
recovery-only. Recovery-only keeps the supervisor parked until a later signed update or
seed clears that marker, then the platform service restarts onto the
repaired slot. An unreadable update journal also enters recovery-only. `run` holds a
separate run lease until the child exits so two supervisors cannot share
the same mailbox; `update` still uses the transaction lock. A later
publish stops the old adapter with SIGTERM and a bounded wait before SIGKILL.
A healthy child that exits while the supervisor is still running is a
supervisor failure so the platform service restarts it. The one-shot decision
is durable across supervisor restarts. It does not enroll or open PostgreSQL. HTTPS is required
except for loopback test origins.

```sh
punaro-bootstrap update \
  --directory /absolute/private/bootstrap \
  --keys-file /absolute/punaro-release.pub
punaro-bootstrap status --directory /absolute/private/bootstrap
punaro-bootstrap rollback --directory /absolute/private/bootstrap
punaro-bootstrap run --directory /absolute/private/bootstrap
```

`--release` may name a catalog-listed release. Automatic update refuses a
stale catalog, an unsigned or digest-mismatched document, a sequence
downgrade, a critical block, and a path outside the origin. Host-local
rollback swaps the two published slots and does not lower the highest
accepted sequences. Automatic rollback from `run` still requires a fresh
catalog listing and loads `{directory}/release.pub` when `--keys-file` is
omitted. Source installers may `seed-checkout` a reviewed local adapter as
`v0.0.0-local`; that identity is not a signed rollback target. Recovery-only
exits successfully so platform services do not restart-loop; a crash after a
healthy child still fails the supervisor so the service can restart.

## Deliberately offline or separately gated

- The production release public key is supplied out of band until an approved
  transition bootstrap embeds it; the private key never enters CI.
- Offline recovery bundles and key-compromise re-key remain a separate
  high-authority process.
- Fleet rollout mutation remains an operator workflow. `fleet-doctor` provides
  the signed, read-only cross-machine release/protocol/schema/plugin/skill gate.
