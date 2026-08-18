# GitHub Releases origin

Punaro's public artifact origin is GitHub Releases. This is the fixed source
`punaro-bootstrap` pulls from. The gateway may name a signed release; it
never supplies a download URL, installer script, or unsigned `latest` pointer.

This is the release-trust slice of
[`client-lifecycle-compatibility-recovery-rfc.md`](client-lifecycle-compatibility-recovery-rfc.md).
It is not yet a signed official release and does not implement enrollment,
fleet rollout, or the recovery HTTP surface.

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

The `release` workflow dispatch builds:

- `punaro-adapter`, `punaro-trusted-attachment`, `punaro-memory`,
  `punaro-enroll`, and `punaro-bootstrap` for `darwin/arm64`, `linux/amd64`,
  `linux/arm64`, and `windows/amd64`
- `punaro` and `punaro-telegram` for Linux

Darwin adapter builds use `CGO_ENABLED=1` so the supported ACL path is compiled
in. The workflow then writes unsigned `punaro-release.json` and
`punaro-catalog.json` and creates a **draft** GitHub Release. The private
release key is not a CI secret and is never placed in this repository.

Unsigned draft bytes are a publication candidate. Bootstrap must fail closed
until both detached signatures are present and verify against a public key
embedded in that bootstrap.

The `catalog` prerelease is overwritten with the newest unsigned catalog so
the origin path stays stable. Replacing it does not make the catalog trusted.

## Cutting a candidate

1. Merge the commit you intend to ship.
2. Run the `release` workflow with an explicit release name and sequence. Do
   not publish by pushing a tag; the workflow is dispatch-only so the sequence
   cannot race a live repo variable. Overlapping dispatch runs queue.
3. Wait for the draft release and the `catalog` prerelease to appear.
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

6. Upload the two `.sig` files to the versioned release and
   `punaro-catalog.sig` to the `catalog` prerelease. Pass that public key set
   to `punaro-bootstrap update --keys-file`. Do not embed a production key
   until the first official signed release exists.
7. An official maintained release still requires the
   [security release gates](security-release-gates.md) and a
   [release-evidence record](release-evidence/README.md). This origin does not
   bypass those gates.

## Local assembly

```sh
./scripts/build-release-artifacts.sh --output-dir ./dist
go run ./cmd/punaro-release assemble \
  --dir ./dist \
  --release v0.1.0 \
  --sequence 1 \
  --catalog-sequence 1
go run ./cmd/punaro-release validate --dir ./dist
```

`assemble` hashes `deploy/compose/production.yaml` and the embedded migration
manifest. A digest-pinned gateway image is optional until GHCR publication
exists; when present it must be `@sha256:` and `release_sha256` must match.

## Bootstrap pull

`punaro-bootstrap` fetches only two-component paths beneath the fixed origin,
verifies the catalog and manifest signatures, checks exact length/digest, and
publishes `current` / `previous` slots. Platform services launch
`punaro-bootstrap run`, which starts the current-slot adapter with the
existing host-local profile. After a previous slot exists, the new current
must write a content-free ready file within 60 seconds; otherwise run rolls
back once when the fresh catalog still lists that previous release, or enters
recovery-only. An unreadable update journal also enters recovery-only. `run` holds a
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

## Still outstanding

- embedding the production public key in that bootstrap
- GHCR image publication and a required `image` digest
- SBOM, provenance attestations, and offline recovery bundles
- gateway desired-release store and fleet rollout
