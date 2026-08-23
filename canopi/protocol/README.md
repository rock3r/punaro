# Canopi event protocol

This directory is the transport-neutral boundary for the provisional Canopi
coding-agent dashboard. Producers may deliver these events over direct HTTP,
Punaro, a local spool, or another transport without changing provider mapping.

The JSON Schema is the wire contract. The Go types and strict validator in
`event.go` implement the same version-1 model and additionally reject sensitive
metadata keys case-insensitively. Prompt text, transcripts, assistant messages,
tool inputs and tool outputs are never required and are rejected from metadata.

Card identity is `(source, machine.id, agent_instance_id)`. `event_id` is the
at-least-once idempotency key; `activity_at`, then `event_id`, orders updates for
the same card. `emitted_at` is diagnostic only and does not make delayed events
newer.

Structural protocol validation is independent of wall-clock and transport.
Collectors apply their configured future-clock-skew bound at admission so an
untrusted timestamp cannot permanently fence correct updates or avoid expiry.
