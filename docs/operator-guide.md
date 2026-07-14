# Operator guide

Punaro currently provides a loopback alpha text relay for enrolled adapters and
a separately deployable Telegram bridge. It is not a released public service
and does not support attachment transfer. Do not use it to carry sensitive
production work yet.

## Run locally

Use Go for the current local smoke test:

```sh
go run ./cmd/punarod
curl --fail http://127.0.0.1:8080/healthz
```

The listener is deliberately restricted to a **literal** loopback IP.
`PUNARO_LISTEN_ADDR` must use `127.0.0.1:8080` or `[::1]:8080`; hostnames such
as `localhost` are rejected until the daemon can verify their resolved address.
A non-loopback address is a configuration error, even for health checks.

Set `PUNARO_RELAY_ENABLED=true` plus a public
`PUNARO_RELAY_MACHINES_JSON` enrollment set to enable the alpha relay; see the
[onboarding guide](alpha-text-relay.md). `PUNARO_DATA_DIR` holds its SQLite
WAL state. `PUNARO_LOG_LEVEL` is validated as `debug`, `info`, `warn`, or
`error`, but does not yet filter the standard logger. An explicitly
named dotenv file is for local development only:

```sh
go run ./cmd/punarod --env-file .env
```

Process environment values override dotenv values.  Never commit, log, or
share a dotenv file, database, backup, private key, token, or message body.

### Signed attachment-directory distribution

The file-transfer API is still disabled. A deployment may, however, exercise
the prerequisite signed directory distribution independently by setting
`PUNARO_DIRECTORY_ENABLED=true` and an absolute
`PUNARO_DIRECTORY_SNAPSHOT_FILE`. The relay must also be enabled with its
normal machine enrollment set. The snapshot parent and file must be private
(`0700` directory, `0600` regular non-symlinked file); the daemon validates the
complete canonical CBOR snapshot on every request and returns no cached
fallback. Publish an updated snapshot by atomically replacing the configured
file. The only endpoint is authenticated `GET /v2/directory`; it requires both
the enrolled machine's signed request and, when configured, Cloudflare Access.

This is a validation aid for enrollment, directory publishing, and revocation
drills. It does not enable attachment permits or attachment transfer, and it
does not relax the attachment release gate.

## Containers and systemd

The Compose file is a hardened build/run baseline, not a public deployment.
It intentionally publishes no port and does not import `.env`; provide only
the specific non-secret configuration a service needs.  The read-only root
filesystem leaves `/var/lib/punaro` as the only persistent writable location.

The supplied systemd unit is likewise a baseline.  Before using it on Linux,
run a smoke test under the target distribution, verify SQLite WAL behavior,
and record `systemd-analyze security punarod.service` together with the exact
systemd version in release evidence.  Every reported exposure must be either
eliminated or have a named, time-bounded security exception; an unreviewed
score or an "inspect" result is not acceptance.  Keep the listener on loopback
and use a separately reviewed ingress only after the public-runtime release
gate is complete.

## Operations and incident response

There is no supported production backup or restore procedure yet.  Do not
claim one.  Before any durable production data is admitted, the release must
provide encrypted backups, integrity verification, a measured restore drill,
disk-pressure limits, credentials rotation, and revocation exercise.

If a credential or machine is suspected compromised, stop the local service,
preserve relevant logs without copying secrets or message bodies, rotate the
credential out of band, and do not re-enable service until the future
directory/revocation workflow has been exercised.
