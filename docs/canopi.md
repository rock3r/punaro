# Canopi coding-agent dashboard MVP

Canopi is a provisional name for Punaro's “what are my agents doing?” feature.
It is implemented inside Punaro because Punaro already owns the cross-machine,
operator, identity, and deployment seams the feature will eventually use. The
MVP remains independently deployable: the protocol, provider mapper, collector,
renderer, simulator, and panel firmware do not depend on Punaro mailboxes or
message types.

## Visual direction

The selected concept establishes the monochrome hierarchy, card treatments,
status symbols, density, and typography direction:

![Selected Canopi monochrome UI concept](assets/canopi-selected-ui.png)

The MVP recreates that direction with deterministic layout, embedded fonts,
one-bit-safe drawing, and live lifecycle data. It does not display or embed the
mock-up in the generated panel image:

![Deterministic 800x480 Canopi implementation](../artifacts/canopi-implementation.png)

See the [visual implementation QA](../design-qa.md) for the normalized
pixel-for-pixel comparison and remaining P3 observation.

## Architecture and boundaries

```text
provider command hook -> bounded durable local spool -> detached retry worker
                                                     -> POST normalized event
                                                     -> Canopi collector/state file
                                                     -> deterministic 800x480 PNG
                                                     -> XIAO conditional GET/panel
```

- `canopi/protocol` is the versioned transport-neutral contract.
- `cmd/canopi` is the collector, durable current-state store and renderer host.
- `cmd/canopi-claude-hook` is the first real provider adapter.
- `cmd/canopi-sim` emits 19 realistic agents across three machines and moves
  one agent between working and permission-waiting on successive ticks.
- `firmware/canopi-panel` is the XIAO ESP32-C3 panel client.

Card identity is `(source, machine.id, agent_instance_id)`. Delivery is
at-least-once. Duplicate event IDs are harmless, and older updates lose to
`activity_at`, then lexicographically to `event_id` on equal timestamps. The
durable JSON snapshot retains the bounded dedupe window across collector
restarts. Non-terminal agents expire instead of becoming successful; terminal
agents have an independent retention period.

The collector sorts the complete state set as waiting, done, working, and then
by descending activity time inside each state. Only after sorting does it apply
grid capacity. When there is overflow, the last slot replaces one agent and
reports counts from the omitted tail, not global totals.

## Privacy and failure behavior

The wire event never requires prompts, transcripts, assistant messages,
credentials, tool inputs, or tool outputs. Metadata is default-deny; the schema
and Go validator accept only the privacy-safe `hook`, `simulated`, and
`agent_type` keys. The
Claude adapter briefly inspects the provider payload locally to classify an
unambiguous final question and to create a keyed HMAC retry identifier; neither
the source text nor an unkeyed source digest is transmitted. Only task title,
optional repository, stable IDs, state, timestamps, and primitive allowlisted
metadata leave the machine.

The hook-facing Claude process performs no network I/O. It normalizes the event,
durably enqueues only that privacy-safe event, starts a detached delivery child,
and returns. One cross-process worker drains the bounded 4,096-event spool and
retries with the same event ID until the collector acknowledges it. Individual
HTTP attempts are bounded; a crashed worker leaves its event queued and a stale
worker lock is recoverable. Missing configuration, malformed provider input,
spool or process-launch failure, token-file failure, network failure, and
collector rejection all leave the coding agent unblocked and produce no
provider-visible output.

All collector routes require the same bearer token. Bodies, batches, headers,
dedupe memory, and grid capacity are bounded. A non-loopback listener must be a
concrete private/link-local IP and requires `--allow-lan`; wildcard and public
binds are rejected. The token path must name a current-user-owned regular file
with owner-only access (or an equivalent protected current-user ACL on Windows);
symlinks and files replaced during open are rejected.

## Run the vertical slice

Create a private token and choose absolute paths:

```sh
umask 077
openssl rand -hex 32 > /absolute/private/canopi.token
```

Run the collector on loopback:

```sh
go run ./cmd/canopi \
  --listen 127.0.0.1:8090 \
  --token-file /absolute/private/canopi.token \
  --state-file /absolute/private/canopi-state.json
```

For a deliberately selected LAN address, add `--allow-lan` and replace the
listener with that concrete private IP. Useful configuration flags are
`--columns`, `--rows`, `--working-ttl`, `--done-retention`,
`--max-live-records`, `--max-future-skew`, `--relative-time-bucket`, and
`--title`. New agent identities are rejected at the configured live-record
ceiling, while updates to known identities remain admissible. Activity times
beyond the configured future-clock-skew window are rejected before they can
fence later correct updates or evade expiry. Expired records are durably purged
before capacity admission, so an offline panel cannot leave the store stuck at
its ceiling.

In another terminal, generate the selected 3 waiting / 4 done / 12 working
overflow state:

```sh
go run ./cmd/canopi-sim \
  --endpoint http://127.0.0.1:8090 \
  --token-file /absolute/private/canopi.token
```

One-shot mode is `--once`. Inspect the normalized snapshot or image with:

```sh
CANOPI_TOKEN="$(cat /absolute/private/canopi.token)"
curl -H "Authorization: Bearer $CANOPI_TOKEN" \
  http://127.0.0.1:8090/v1/snapshot
curl -H "Authorization: Bearer $CANOPI_TOKEN" \
  -o canopi.png \
  http://127.0.0.1:8090/v1/render/800x480.png
```

The supported endpoints are `POST /v1/events`, `POST /v1/events:batch`,
`GET /v1/snapshot`, and `GET /v1/render/800x480.png`. Both GET routes return
strong ETags and honor `If-None-Match` with a body-free 304. A structurally valid
batch continues after per-event admission failures and returns `207` with an
ordered status/result entry for every event, so one permanent rejection cannot
starve later lifecycle updates. Persistence failure still fails the request.

## Claude Code adapter

The adapter was validated against Claude Code 2.1.197 and the corresponding
first-party hook reference. It consumes the common `session_id`, `cwd`, and
`hook_event_name` fields plus current event-specific fields:

- `PermissionRequest` -> waiting / permission;
- `Elicitation` and input-requiring `Notification` variants -> waiting;
- prompt, tool, batch, session and subagent-start activity -> working;
- `Stop`, `TaskCompleted`, and `SubagentStop` -> done unless the local
  deterministic classifier sees a clear user question.

Build the adapter and export its small, non-secret configuration in the shell
that launches Claude Code:

```sh
go build -trimpath -o /absolute/bin/canopi-claude-hook ./cmd/canopi-claude-hook
export CANOPI_ENDPOINT=http://10.0.0.20:8090
export CANOPI_TOKEN_FILE=/absolute/private/canopi.token
export CANOPI_SPOOL_DIR=/absolute/private/canopi-claude-spool
export CANOPI_MACHINE_ID=studio-m2
export CANOPI_MACHINE_LABEL=studio-m2
export CANOPI_TASK_TITLE='Punaro / current task'
export CANOPI_REPOSITORY='rock3r/punaro'
```

Copy the `hooks` object from
`canopi/providers/claude-code-hooks.example.json` into project-local
`.claude/settings.local.json` or the desired Claude settings scope, then replace
the absolute binary path. Hook stdout and stderr stay empty.

`CANOPI_SPOOL_DIR` is optional; when omitted, the adapter creates
`canopi-claude-spool` beside the token file. The directory and queued normalized
events are owner-only. A collector outage never causes the hook-facing process
to wait for network recovery. The adapter applies the same current-user,
owner-only, regular-file, no-symlink token checks as the collector.

Run the durable worker as a continuously supervised companion using the same
environment (for example with `Restart=always`/`KeepAlive` in the host service
manager):

```sh
/absolute/bin/canopi-claude-hook supervise
```

Hooks also kick-start this singleton worker opportunistically. The persistent
supervisor is the durable wake path: it keeps polling an empty spool, retries
collector outages, and is restarted by the service manager if the worker
crashes, so the final event of a quiet session does not depend on a later hook.

## Pi evaluation

Pi 0.84.2 type definitions were inspected directly rather than copied from the
handoff. They expose `session_shutdown`, `agent_start`,
`agent_end`, `agent_settled`, `turn_start`, `turn_end`, `tool_call`,
`tool_result`, and tool-execution events.

`hsingjui/pi-hooks` was reviewed at commit
`8250a856d4f892f0a8a640ac2f1241d1a000701b` (package version 0.0.1). It is a
good reuse path for this MVP's `SessionStart`, `UserPromptSubmit`, tool, `Stop`,
and `SessionEnd` command hooks, and its `Stop` payload includes
`last_assistant_message`. It does not map Pi permission UI or notification
events, supports command hooks only, and implements stop control best-effort.
Therefore the next Pi slice should pin that reviewed commit for working/done
reuse, then add a very small native Pi extension only if accurate
waiting-for-user signals are required. Do not fork a full bespoke hook bridge.

The protocol already reserves `pi`, `codex`, and `grok_build` sources, so those
adapters need no collector changes.

## Panel firmware and exact hardware verification

The source targets Seeed's XIAO 7.5-inch monochrome ePaper Panel: XIAO
ESP32-C3, UC8179, 800x480, `BOARD_SCREEN_COMBO 502`. It uses the official
Seeed_GFX API and PNGdec. Dependency commits are pinned in `platformio.ini`.
Arduino ESP32 2.0.17 requires Espressif GCC 8.4's `rv32imc/ilp32` multilib.
The handoff's native GCC 12 workaround compiled, but its selected `libgcc`
contained an `frrm` instruction that the integer-only ESP32-C3 cannot execute,
causing a trap during Wi-Fi setup.
PlatformIO's registry package for GCC 8 is x86_64 on this Apple Silicon Mac, so
the project installs Espressif's official matching macOS arm64 archive and
verifies its published SHA-256. The assembler is explicitly kept on the legacy
RISC-V 2.2 ISA model while `-march=rv32imc` selects the no-FPU multilib.

The upload path also pins Espressif OpenOCD 0.12.0-esp32-20260703. PlatformIO's
2022 OpenOCD could attach to this XIAO but could not probe its flash when the
e-paper board affected the ESP32-C3 strap pins. The pinned release contains
Espressif's strap-safe C3 flasher fix. Both tools are installed locally and
gitignored; no Rosetta installation is required.

The client connects to Wi-Fi, sends the bearer token and retained ETag, and does
nothing on 304. A 200 response must be `image/png`, have a bounded known length,
decode successfully, and report exactly 800x480 before `epaper.update()` runs.
The new ETag is retained only after a successful full display refresh. USB mode
polls every 20 seconds. Optional battery mode sleeps for three minutes by
default; the ETag is retained in RTC memory.

Physical verification:

1. Run Canopi on a concrete private LAN address with `--allow-lan`, start the
   simulator, and verify from another LAN machine that the render URL returns a
   1-bit 800x480 PNG and an ETag.
2. Copy `firmware/canopi-panel/include/secrets.example.h` to `secrets.h` and set
   Wi-Fi, the LAN render URL, and the same token. The real file is gitignored.
3. Connect the panel by USB-C. Keep it USB-powered for the MVP. If the panel was
   assembled separately, seat the fragile FPC with metal contacts facing up.
4. On Apple Silicon, from `firmware/canopi-panel`, run
   `./install-toolchain-macos-arm64.sh` once. It downloads the exact GCC and
   OpenOCD archives, verifies both SHA-256 values, and prints their versions.
5. Run `platformio run`, then `platformio run --target upload`, then
   `platformio device monitor --baud 115200`. Upload uses the XIAO's built-in
   JTAG, so the BOOT button is not required. If the board does not start after
   JTAG reset, fully cycle its power; switching or cycling USB is not a cold
   cycle while a connected battery and its switch keep the board powered.
6. Confirm the first fetch performs exactly one full refresh and the displayed
   layout matches `artifacts/canopi-implementation.png` without clipping,
   rotation, grey pixels, or missing rows.
7. Leave state unchanged for at least two 20-second polls. The screen must not
   flash or refresh; the server response is 304 because the firmware sends
   `If-None-Match`.
8. Change one simulated agent. Confirm one refresh within 20 seconds, a new
   ETag, and no additional refresh on the following unchanged poll.
9. Stop simulator updates and wait past `--working-ttl`; confirm non-terminal
   cards disappear rather than becoming done. Leave a done card past
   `--done-retention` and confirm it disappears independently.

The physical XIAO panel was built, flashed through built-in JTAG, and exercised
end to end. The final image used 87,196 of 327,680 RAM bytes and 939,818 of
1,310,720 flash bytes. Disassembly confirmed the linked image contains no
floating-point CSR instructions. Serial evidence showed a successful validated
display refresh, repeated body-free 304 responses with no display update,
further refreshes after the simulator changed lifecycle state, and 304
responses again after the simulator stopped.

Deployment-specific SSIDs, credentials, network names, firewall identifiers,
client addresses, and host addresses are intentionally excluded from the
repository. Operators should substitute their own concrete private addresses
and enforce the narrowest route from the panel network to the collector's TCP
listener.

## Renderer provenance

The deterministic renderer embeds Roboto Mono Regular and Bold from the
official repository at commit `895ec691990d041dd727c7b5afa3ce56525d98e6`
under the bundled SIL Open Font License. SHA-256:

- Regular: `af0bff7599c3df3831755c16e39b3c496df74b8c8d8a1161b14dc8461be17cb4`
- Bold: `3ecf35e5e87accc7578b605d1f5f0bc30d88b195d6807bec8a0c57f6aa95c4db`

Text is rasterized server-side, thresholded into a two-entry palette, and PNG
encoded deterministically. The panel never displays the selected mock-up.
