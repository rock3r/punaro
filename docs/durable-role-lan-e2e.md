# Durable-role LAN release-candidate validation

This opt-in runbook validates durable conversation-role replacement against an
already deployed release candidate. It does not provision a relay, create
credentials, change an adapter profile, or infer topology. Run it only with
the owner-managed deployment configuration on `mac-studio`, `coso`, and
`mattone`; replace every all-caps placeholder locally and do not record its
value in this file, shell history, CI output, or the release record.

## Preconditions and discovery

Before creating any state, run these read-only checks from the candidate
checkout. They establish which host runs `punarod`, which hosts run adapters,
the active service manager, and that all three copies identify the same clean
candidate commit. Do not continue if the relay host, adapter host, or candidate
cannot be identified, or if the deployed commit differs from the checkout that
runs the tests.

```sh
for host in mac-studio coso mattone; do
  ssh "$host" 'hostname; uname -s; git -C PATH_TO_PUNARO rev-parse HEAD; git -C PATH_TO_PUNARO status --porcelain; pgrep -fl "punarod|punaro-adapter" || true; systemctl --user is-active punaro-adapter 2>/dev/null || true; systemctl is-active punarod 2>/dev/null || true; launchctl print gui/$(id -u)/org.punaro.adapter 2>/dev/null | sed -n "1,2p" || true'
done
```

Use the existing owner-managed service and private configuration in place. Do
not print relay URLs, Access headers, machine keys, DSNs, mailbox bodies, or
production conversation IDs. Record only the candidate commit, image digest,
host role (`relay` or `adapter`), service health result, and redacted command
outcome. Confirm relay readiness and adapter health before and after every
scenario.

Choose a unique opaque run suffix, then derive a disposable conversation,
three disposable endpoint aliases, three role names, and harmless opaque probe
tokens from it. The aliases must be in each enrolled machine's existing
namespace. Do not reuse a production alias or role name.

## Durable-role replacement

1. From `mac-studio`, create one disposable conversation with its attached
   sender endpoint as `send,receive,admin` and a role member owned by `coso`
   with `send,receive`. Use a fresh idempotency key. Bind the role on `coso`
   to an attached disposable session using `punaro-adapter bind-role`.
2. Send one opaque harmless probe from `mac-studio`. On `coso`, verify exactly
   one local durable mailbox handoff whose server-derived `recipient_role`
   names the selected role, and acknowledge it using the supported mailbox
   control. Do not infer that role from the untrusted message body. Retrying
   the same send with the same key must not inject a second mailbox item; a
   different request reusing that key must fail.
3. Detach the first `coso` test session through its normal adapter or mailbox
   lifecycle. Attach a replacement session in the same enrolled namespace,
   advertise it, and bind the same role to it. Do not edit conversation
   membership. Send a second opaque probe and verify that only the replacement
   session receives and acknowledges it.
4. Attempt fetch/lease, acknowledgement, and send using the detached first
   session. Each must fail with the normal authorization failure and must not
   create a delivery, message, lease, or acknowledgement. The replacement
   session remains able to send and receive as the role.
5. Repeat steps 1–4 with a role owned by `mattone`. Use native PowerShell for
   commands run on `mattone` and short shell-native `ssh` commands only for
   remote invocation. This proves the durable role is tied to its owning
   machine rather than to a macOS-only session convention.

The initial and replacement bindings must never both authorize a role lease.
If a delivery is leased immediately before replacement, the stale lease must
be fenced and the replacement session may re-lease it; do not treat a stale
acknowledgement as success.

## Compatible mail and cleanup

During the same isolated run, use attached disposable endpoint members to
exercise one harmless bidirectional message for each host pair. Verify the
normal endpoint-member path remains unchanged, acknowledgement is durable, a
same-key retry is deduplicated, and a short supported adapter stop/start causes
eventual delivery without a duplicate mailbox injection. Targeted role
delivery must reach only its selected role;
untargeted broadcast must still reach compatible endpoint members.

Exercise retired attachment controls only as a fail-closed boundary unless the
candidate already exposes an approved attachment runtime. Unsupported routes
and controls must be rejected without durable state. Run the existing private
remote-MCP release-candidate E2E configuration against this same commit; if
the candidate intentionally disables memory transport, record its fail-closed
result rather than replacing it with an offline harness.

After recording redacted outcomes, remove every disposable endpoint member
that the conversation control API supports and detach every test alias from
the actual groups currently attached to the adapters. Verify those attached
groups contain zero active disposable aliases. If the candidate has no
supported conversation-delete or durable-role-member removal operation, do
not edit relay storage directly; record the isolated final admin and role
metadata as residual test state instead. Confirm all three adapter services
and relay readiness remain healthy. Record the candidate commit/image, host
roles, redacted commands, pass/fail outcomes, achieved cleanup, residual risk,
and the owner-managed rollback reference in a personal
`deployment-validation` record. Only an independently approved official
release belongs under `release-evidence`.
