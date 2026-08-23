# Canopi event protocol

This directory is the transport-neutral boundary for the provisional Canopi
coding-agent dashboard. Producers may deliver these events over direct HTTP,
Punaro, a local spool, or another transport without changing provider mapping.

The JSON Schema is the wire contract. The Go types and strict validator in
`event.go` implement the same version-1 model. Metadata is default-deny: only
the privacy-safe `hook`, `simulated`, and `agent_type` keys are accepted by both definitions.
Prompt text, transcripts, assistant messages, credentials, tool inputs, tool
outputs, and unrecognized provider fields have no wire representation.
JSON numeric metadata is decoded as an exact `json.Number`, so schema-valid
integers are never rounded through IEEE-754 conversion during ingestion or a
durable-store restart. Metadata may be omitted, but an explicit JSON `null` is
rejected because the published schema requires an object when the field is present.

Card identity is `(source, machine.id, agent_instance_id)`. `event_id` is the
at-least-once idempotency key; `activity_at`, then `event_id`, orders updates for
the same card. `emitted_at` is diagnostic only and does not make delayed events
newer.

Structural protocol validation is independent of wall-clock and transport.
Collectors apply their configured future-clock-skew bound at admission so an
untrusted timestamp cannot permanently fence correct updates or avoid expiry.
