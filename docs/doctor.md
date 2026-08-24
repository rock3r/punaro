# Punaro doctor

Punaro doctor is a read-only, content-free readiness contract for one server,
client adapter, bootstrap supervisor, Telegram gateway, or a collected fleet.
It does not repair, enroll, restart, update, roll back, open message bodies, or
print credentials. Remediation values are stable identifiers for an operator;
they are not commands and grant no authority.

## Report and exit contract

Every component writes one strict JSON schema-version `1` report to stdout.
The report is at most 64 KiB and contains at most 128 unique, sorted checks.
Unknown fields, duplicate fields, trailing JSON, noncanonical ordering, unsafe
identity values, and free-form check text are rejected. Identity may contain
only bounded machine, platform, release/sequence, catalog, protocol, schema,
artifact, plugin, skill-set, and capability identifiers.

Each check has a stable `code`, `status` (`pass`, `fail`, or `unavailable`), a
`required` boolean, and for non-passing checks one stable `remediation` code.
An unavailable required dependency is unhealthy. An explicitly optional absent
state, such as a previous slot before the second release, does not make the
component unhealthy.

- Exit `0`: every required check passed.
- Exit `1`: a valid report contains a failed or required-unavailable check.
- Exit `2`: invalid invocation or no trustworthy report could be produced.

All component deadlines are bounded to 1–30 seconds. Network probes use signed
non-consuming nonces and read-only protocol handshakes. Local SQLite checks use
a read-only connection and bounded queries. Installed mailbox smoke checks run
the fixed MCP initialize/tools-only and group-membership exchanges against a
transactionally consistent private SQLite snapshot. Normal concurrent writes
continue against the live mailbox without creating a false diagnostic failure;
the snapshot is acquired through a read-only live connection, and any
application-state write attempted by the probe is contained in the disposable
snapshot and removed afterward.
Backup contents, mailbox state, and nested skill trees are traversed in bounded
directory batches with total-entry ceilings and deadline checks between reads.
Skill-set digests length-prefix every relative path and file body so arbitrary
skill bytes cannot create an ambiguous tree encoding. Explicit bootstrap public
keys and bootstrap health state are read as bounded regular non-symlink files
through the same diagnostic deadline and descriptor-identity checks.
Server installation-path validation, storage-capacity inspection, complete
backup listing and verification, PostgreSQL credential files, adapter plugin
trees, the complete adapter mailbox snapshot/MCP inspection, and the complete
bootstrap diagnostic are inspected in deadline-isolated child helpers. A
stalled mount during `Lstat`, `Statfs`, open, walk, or read
therefore yields unavailable checks (or no bootstrap report) instead of
extending the advertised total deadline; DSN values remain in a private
parent/child pipe and are never printed in the report or logs.

## Commands

Server on the Punaro host:

```sh
punaro doctor-profile write \
  --out /absolute/private/server-doctor.env \
  --relay-url https://punaro.example \
  --machine-id server-doctor \
  --private-key-file /absolute/private/server-doctor.key \
  --access-token-file /absolute/private/server-doctor-access.env

punaro doctor \
  --directory /absolute/private/installation \
  --machine-id punaro-lxc \
  --relay-profile /absolute/private/server-doctor.env \
  --timeout 20s
```

`--machine-id` is required and is the stable public identity used to match this
report in fleet doctor. A separately deployed Telegram gateway is the default;
its local-service checks are optional in the server report and its own
`punaro-telegram doctor` report is authoritative. Add `--gateway-co-located`
only when this server host is explicitly expected to own and run the local
`punaro-telegram` system service.

An Internet/proxy installation also needs `--relay-profile` so the edge checks
probe the real public route, origin, and Access admission. When relay is
enabled, the same probe also requires the enrolled relay identity and protocol.
Access admission passes only after a credentialed request reaches the expected
Punaro route and a fresh equivalent request without the Access credential is
rejected before Punaro can echo its nonce or origin signature. This negative
probe is also required by adapter and Telegram relay and notification checks;
an origin that remains reachable without Access fails the Access check. A
non-loopback HTTPS client with no Access pair also fails admission; only
loopback or explicitly declared trusted-LAN HTTP transport treats Access as not
applicable.
When relay is intentionally disabled, those two relay-only checks are optional
and unavailable; the public-edge checks use the content-free non-relay root
route instead. The profile writer refuses replacement, creates mode
`0600` on Unix, validates every referenced credential before writing, and
prints no credential value. Its relay machine must already be enrolled when
relay is enabled and the signed read-only handshake is required. The referenced
private-key file contains exactly one unpadded base64url Ed25519 private key.
The protected Access file contains
exactly these two lines (with the actual values supplied by the operator):

```text
PUNARO_CF_ACCESS_CLIENT_ID=VALUE
PUNARO_CF_ACCESS_CLIENT_SECRET=VALUE
```

All three files must be absolute, regular, non-symlinked, non-empty, bounded,
owner-only on Unix, and read through the single doctor deadline with descriptor
identity revalidation. The generated profile contains only the fixed HTTPS
origin, machine ID, and those two absolute credential-file paths; credential
contents never enter argv, the profile, the report, or logs. A trusted-LAN
installation with no public URL passes the edge checks from its declared local
topology and omits `--relay-profile`. If relay is enabled in that topology,
relay enrollment and protocol remain required but unavailable until a signed
relay probe can be configured; doctor never synthesizes those checks as passing.

Client adapter on macOS, Linux, or Windows (pass the installed plugin root so
plugin and skill parity are checked):

```sh
punaro-adapter doctor \
  --bootstrap-directory /absolute/private/bootstrap \
  --plugin-root /absolute/installed/punaro-plugin \
  --timeout 20s
```

Bootstrap only:

```sh
punaro-bootstrap doctor \
  --directory /absolute/private/bootstrap \
  --keys-file /absolute/private/release.pub \
  --machine-id MACHINE \
  --timeout 20s
```

Telegram gateway:

```sh
punaro-telegram doctor --timeout 15s
```

On Windows the gateway service checks bind the `Punaro Telegram` scheduled
task to `%LOCALAPPDATA%\Punaro\bin\punaro-telegram.exe` and obtain release
identity from that exact executable, not from a Unix compatibility path.

Collect each JSON file on its own machine. Do not collect raw logs or message
state. Then aggregate locally against the exact signed catalog and manifests:

```sh
punaro-bootstrap fleet-doctor \
  --report server.json --expect punaro-lxc/server \
  --report studio-adapter.json --expect mac-studio/adapter \
  --report studio-bootstrap.json --expect mac-studio/bootstrap \
  --catalog punaro-catalog.json \
  --catalog-signature punaro-catalog.sig \
  --release-root /absolute/verified/releases \
  --keys-file /absolute/private/release.pub
```

Repeat `--report` and `--expect` for every required machine/component pair.
Fleet doctor does not contact machines. It rejects missing or duplicate
identities, untrusted release documents, catalog/release mismatch, unsupported
upgrade edges, protocol/schema skew, or plugin/skill drift.

## Stable check-code registry

This registry names every check family emitted by schema version 1. Operators
should key automation on these codes, status, and requiredness—not on process
logs or ordering.

### Server

Installation and provenance: `installation_configuration`,
`installation_directory`, `installation_paths`, `data_directory`,
`backup_directory`, `attachment_blob_directory`,
`attachment_blob_containment`, `storage_directory_separation`,
`storage_credential_isolation`, `daemon_environment`, `compose_override`,
`compose_manifest_binding`, `migration_manifest_binding`,
`image_digest_binding`, `installed_release`, `running_image`,
`machine_identity`.

For native release artifacts, `installed_release` compares the exact
digest-pinned image embedded after publication. For the operator binary inside
the image itself, whose own digest cannot be known before that image exists,
it binds the release-tagged repository identity known at build time and
requires the installation to use a digest-pinned image from that exact
repository. Compose manifest hashing runs in a deadline-isolated helper, so a
stalled mounted file cannot extend the total doctor timeout.

Database, storage, and update recovery: `database_connection`,
`database_listener_private`, `administration_listener_private`,
`database_owner`, `database_pair`,
`database_schema`, `postgres_major`, `storage_capacity`, `verified_backup`,
`backup_freshness`, `maintenance_fence`, `host_update_stage`,
`update_transaction`, `recovery_receipt`, `update_recovery`,
`owner_credential_file`, `application_credential_file`,
`attachment_blob_directory`, `blob_storage_private`.

`postgres_major` passes only when the running server reports the exact major
compiled into that release and used by its release manifest; accepting any
newer generic PostgreSQL floor would hide restore or partial-upgrade drift.
`database_listener_private` and `administration_listener_private` query
PostgreSQL's effective `listen_addresses` through the application and owner
connections respectively; every configured TCP address must be localhost or a
literal loopback address.

Service and edge: `health_endpoint`, `readiness_endpoint`,
`health_listener_private`, `tunnel_route`,
`tunnel_origin`, `access_admission`, `relay_enrollment`, `relay_protocol`,
`gateway_service_installed`, `gateway_service_enabled`,
`gateway_service_running`, `gateway_service_executable`,
`gateway_service_last_exit`, `gateway_service_restart_state`,
`gateway_release`. These gateway checks are required only with the explicit
server `--gateway-co-located` declaration; otherwise they are optional and the
separate Telegram component report supplies gateway readiness.
For a co-located gateway, `gateway_service_executable` verifies both the base
unit and systemd's effective `ExecStart`, including drop-ins, before the fixed
installed binary's release identity is considered sufficient.

### Adapter

Local configuration: `adapter_configuration`, `adapter_profile_file`,
`adapter_data_directory`, `machine_credential_file`, `client_identity_file`,
`installer_path_aliases`, `mailbox_executable`, `mailbox_state_directory`,
`mailbox_mcp`.

Relay and attachment state: `relay_transport`, `relay_origin`, `relay_access`,
`relay_enrollment`, `relay_protocol`, `notification_transport`,
`notification_origin`, `notification_access`, `notification_enrollment`,
`notification_protocol`, `endpoint_attachment`, `expired_endpoint_bindings`,
`expired_role_bindings`.

`endpoint_attachment` is the required current-state gate. It reads the bounded
active membership set from the configured local mailbox group and verifies
every exact current endpoint with a signed relay endpoint probe; a stale lease
for some other endpoint cannot satisfy the gate. The two `expired_*`
checks are informational and optional because normal endpoint or role
retirement leaves durable tombstones for referential and audit history; their
presence alone does not make an otherwise current adapter unhealthy. They
remain visible so an operator can inspect unexpected retirement history
without exposing endpoint or role inventory in the report.

Service, release, and plugin state: `adapter_service_installed`,
`adapter_service_enabled`, `adapter_service_running`,
`adapter_service_executable`, `adapter_service_last_exit`,
`adapter_service_restart_state`, `bootstrap_selected_artifact`,
`bootstrap_running_artifact`, `bootstrap_supervisor`, `installed_release`,
`portable_plugin_registration`, `codex_plugin_registration`,
`claude_plugin_registration`, `plugin_launcher`, `plugin_version`,
`skill_set_parity`.

`plugin_launcher` requires the platform launcher to be a safe executable and
requires the exact bytes of both POSIX/Windows launchers and both MCP
registration files to match the digest embedded by the release builder.

The adapter runs `version` on the fixed installer-owned `punaro-bootstrap`
executable under the shared diagnostic deadline and passes that identity into
the bootstrap compatibility checks. It does not substitute the adapter's
release identity for `minimum_bootstrap_release`. On Linux, the executable
check also binds systemd's effective `ExecStart`, including drop-ins, to the
exact bootstrap run command. On Windows, it structurally parses the scheduled
task and requires one exact PowerShell action whose `-File` target is the
protected installed runner, and the complete runner content must match the
release-bound canonical script (LF and CRLF are equivalent). Comments, dead
branches, extra commands, or altered exit handling therefore fail the executable
check. On macOS, it structurally decodes the installed plist's exact `Label` and
three-element `ProgramArguments`, then also binds launchd's effective loaded
program and arguments so a stale loaded job cannot pass from an unrelated
matching string.

### Bootstrap

`bootstrap_directory`, `bootstrap_lock`, `run_lock`, `disk_space`,
`release_keys`, `accepted_state`, `current_slot`, `previous_slot`,
`journal_state`, `recovery_state`, `candidate_state`, `swap_state`,
`catalog_reachability`, `catalog_signature`, `catalog_freshness`,
`catalog_sequence`, `current_catalog_allowed`, `current_critical_block`,
`current_manifest_signature`, `current_platform_compatibility`,
`minimum_bootstrap_release`, `minimum_recovery_protocol`,
`current_artifact_integrity`, `previous_catalog_allowed`,
`previous_critical_block`, `previous_manifest_signature`,
`previous_platform_compatibility`, `previous_artifact_integrity`,
`rollback_available`, `running_artifact`, `supervisor_process`,
`candidate_health`.

Compose-manifest hashing and bootstrap slot inspection reject non-regular or
linked paths before opening files and use bounded incremental reads. Both the
standalone bootstrap doctor and the adapter's embedded bootstrap checks run the
complete inspection in a deadline-isolated child, so a synchronous filesystem
operation cannot outlive the single command deadline.

### Telegram gateway

Configuration, service, and upstreams: `telegram_configuration`,
`machine_credential_file`, `bot_credential_file`, `access_credential_file`,
`single_user_policy`, `gateway_endpoint_identity`,
`gateway_endpoint_attachment`, `installed_release`, `running_release`,
`gateway_service_installed`, `gateway_service_enabled`,
`gateway_service_running`, `gateway_service_executable`,
`gateway_service_last_exit`, `gateway_service_restart_state`, `bot_api`,
`relay_transport`, `relay_origin`, `relay_access`, `relay_enrollment`,
`relay_protocol`, `notification_transport`, `notification_origin`,
`notification_access`, `notification_enrollment`, `notification_protocol`.
On Linux, `gateway_service_executable` verifies both the installed unit and
systemd's effective `ExecStart`, so a drop-in cannot redirect the running
service while leaving the base unit apparently valid. On macOS, it
structurally decodes the installed LaunchAgent's exact `Label` and
single-element `ProgramArguments`, then binds launchd's effective loaded
program and arguments to the same fixed gateway executable.

Durable state opening, integrity queries, and liveness aggregation run in a
deadline-isolated child helper; a stalled SQLite path becomes unavailable
instead of extending the total doctor timeout. Durable state and liveness:
`state_integrity`, `conversation_route_integrity`,
`cycle_liveness`, `successful_cycle_liveness`, `polling_liveness`,
`relay_cycle_liveness`, `telegram_cycle_liveness`, `retry_state`,
`terminal_inbound_rejection`, `terminal_outbound_rejection`,
`stuck_head_delivery`, `message_less_update_stall`, `deleted_topic_target`,
`transient_retry_stall`, `claim_backlog`, `claim_backlog_age`.
Inbound poll-offset progress and outbound delivery-head progress use separate
durable clocks, so continuous new Telegram updates cannot hide a repeatedly
failing outbound head. Endpoint-specific relay attachment probes bind the exact
asserted endpoint into the machine signature; changing that header invalidates
the probe rather than exposing an endpoint-enumeration oracle.

### Fleet

`report_inputs`, `component_health`, `expected_components`,
`machine_identity_uniqueness`, `release_catalog_membership`, `release_skew`,
`protocol_skew`, `protocol_compatibility`, `schema_skew`, `upgrade_edges`,
`plugin_skew`, `skill_set_skew`.
Every component report must carry a non-zero protocol identity; an omitted
identity fails `protocol_compatibility` instead of being excluded from the
comparison. Every server report must likewise carry a non-zero storage schema
identity inside the signed policy range; omission or incompatibility fails
`schema_skew`.

## Stable remediation registry

The report supplies exactly one of the following identifiers for every
non-passing check. They describe the next operator decision; none is executable
and none authorizes an agent to perform the action. Use the supported installer,
service manager, update/recovery command, or provider console only after the
operator explicitly approves that separate action.

- Observation only: `collect_gateway_report`, `inspect_adapter_service_exit`,
  `inspect_gateway_retry_state`, `inspect_gateway_service_exit`, and
  `inspect_update_recovery` mean collect the corresponding content-free local
  service/update state before choosing a mutation.
- Release and provenance: `install_allowed_release`, `install_catalog_release`,
  `install_compatible_gateway_release`, `install_compatible_release`,
  `install_matching_plugin`, `install_matching_release`,
  `install_matching_skill_set`, `install_platform_release`,
  `install_release_keys`, `install_second_signed_release`,
  `install_signed_release`, `install_unblocked_release`,
  `repair_release_catalog`, `repair_release_manifest`,
  `repair_release_origin`,
  `reinstall_release_compose_manifest`,
  `reinstall_release_migration_manifest`, `reinstall_signed_release`,
  `refresh_release_catalog`, `upgrade_bootstrap_protocol`, and
  `upgrade_bootstrap_release` mean select only catalog-allowed, signature- and
  digest-verified bytes through the bootstrap/release lifecycle. Never replace
  a slot or manifest by hand.
- Service lifecycle: `install_adapter_service`, `enable_adapter_service`,
  `start_adapter_service`, `restart_adapter_service`,
  `install_gateway_service`, `enable_gateway_service`,
  `start_gateway_service`, `restart_gateway_service`,
  `restart_gateway_release`, `restart_with_installed_image`,
  `repair_adapter_service_binding`, `repair_adapter_service_restart`,
  `repair_gateway_service`, `repair_gateway_service_binding`, and
  `repair_gateway_service_restart`, `repair_server_service`, and
  `repair_server_readiness` mean reconcile the reviewed fixed service
  definition and release binding with the platform service manager. Preserve
  owner/user context and inspect last exit before restarting.
- Client installation and local state: `install_adapter_profile`,
  `install_client_identity`, `repair_adapter_configuration`,
  `repair_adapter_data_directory`, `repair_installer_paths`,
  `repair_mailbox_configuration`, `repair_mailbox_executable`,
  `repair_mailbox_mcp`, `repair_mailbox_state_directory`,
  `repair_plugin_registration`, `repair_codex_plugin_registration`,
  `repair_claude_plugin_registration`, `repair_plugin_launcher`,
  `repair_bootstrap_directory`, `repair_bootstrap_lock_state`,
  `repair_bootstrap_state`, and `repair_previous_slot` mean stop and use the
  reviewed installer or documented bootstrap recovery path. Do not weaken
  owner-only modes/ACLs, follow aliases, overwrite local mailbox state, or edit
  slot records.
- Relay, edge, and identity: `configure_server_machine_identity`,
  `enable_relay_to_require_relay_checks`,
  `repair_access_service_auth`, `repair_server_doctor_enrollment`,
  `repair_tunnel_route`, `repair_tunnel_device_route`,
  `restart_endpoint_attachment`, `restart_gateway_attachment`,
  `inspect_retired_endpoint_bindings`, `inspect_retired_role_bindings`, plus
  the generated families
  `repair_relay_transport`, `repair_relay_route`, `repair_relay_access`,
  `repair_relay_enrollment`, `repair_notification_transport`,
  `repair_notification_route`, `repair_notification_access`, and
  `repair_notification_enrollment`, mean reconcile the exact existing origin,
  Access policy, enrollment, protocol, and attachment/role lifecycle. Never
  issue a new credential, widen ingress, invent an endpoint, or change routing
  merely because doctor reported the identifier.
  `enable_relay_to_require_relay_checks` describes why a relay-disabled check
  is optional; enable relay only when that deployment mode is actually wanted.
- Server paths and topology: `repair_installation_configuration`,
  `repair_installation_directory`, `repair_installation_paths`,
  `repair_data_directory`, `repair_backup_directory`,
  `repair_attachment_blob_directory`, `repair_owner_credential_file`,
  `repair_application_credential_file`, `regenerate_server_configuration`,
  `separate_data_and_backup_directories`, `separate_storage_and_credentials`,
  `repair_database_listener_topology`, `repair_health_listener_topology`,
  `repair_administration_listener_topology`, and
  `repair_blob_storage_topology` mean restore the documented private,
  non-overlapping, owner-bound installation shape. Never make a listener public
  or relax a credential/path permission to make a check pass.
- Database, backup, and update recovery: `repair_database_connection`,
  `repair_database_owner`, `repair_database_pair`, `repair_database_schema`,
  `install_release_postgres_major`, `create_verified_backup`,
  `refresh_verified_backup`, `repair_update_recovery_receipt`,
  `resume_or_recover_update`, `resume_abort_or_recover_update`,
  `run_supported_update_or_recovery`, `resume_or_recover_bootstrap`, and
  `recover_bootstrap` mean keep the maintenance fence closed and resume the
  exact durable transaction, supported abort, or verified-backup recovery.
  Never delete stages/receipts, run migrations directly, or start an obsolete
  writer against newer state.
- Capacity: `free_server_storage` and `free_bootstrap_disk_space` mean the
  operator must free space outside protected live state or provision capacity;
  doctor never deletes files.
- Telegram credentials and durable state: `install_access_credential_file`,
  `install_bot_credential_file`, `repair_telegram_configuration`,
  `repair_bot_api_access`, `repair_conversation_routes`,
  `repair_deleted_topic_route`, `repair_gateway_retry_state`,
  `repair_inbound_relay_authorization`, `repair_message_less_polling`,
  `repair_outbound_telegram_target`, `repair_stale_gateway_claims`,
  `repair_stuck_gateway_delivery`, `repair_telegram_polling`,
  `repair_transient_gateway_dependency`, `restore_gateway_state`, and
  `resume_gateway_claims` mean use the gateway's documented operator recovery
  flow while preserving offsets, deduplication, claims, routes, and single-user
  policy. Never create a replacement topic, send a test message, expose a bot
  credential, or edit SQLite rows manually.
- Fleet coordination: `collect_missing_reports`, `remove_duplicate_reports`,
  `repair_unhealthy_components`, `install_catalog_release`,
  `complete_fleet_update`, `complete_server_update`,
  `follow_supported_upgrade_edge`, `install_compatible_release`,
  `install_matching_plugin`, and `install_matching_skill_set` mean correct the
  independently diagnosed machine first, recollect its report, and aggregate
  again against the same signed policy. Fleet doctor never reaches into or
  mutates another machine.

## Acting on a report

Preserve the JSON and the signed release documents used for fleet aggregation.
Investigate the first relevant failed dependency family, but do not assume
lexical check ordering is causal. A downstream `unavailable` usually means its
prerequisite could not be proven. Repair, restart, enrollment, routing, update,
rollback, credential, and Telegram-topic changes remain separate explicit
operator actions. Rerun the same component doctor after an authorized repair,
then rerun fleet doctor before rollout or release evidence is accepted.
