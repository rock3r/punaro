#!/bin/sh
set -eu

release_gate_fixture=$(mktemp -d "${TMPDIR:-/tmp}/punaro-release-gates-test.XXXXXXXX")
trap 'rm -rf "$release_gate_fixture"' EXIT HUP INT TERM

mkdir -p "$release_gate_fixture/bin" "$release_gate_fixture/docs/release-evidence"
cp scripts/verify-release-gates.sh "$release_gate_fixture/verify-release-gates.sh"

printf '%s\n' \
	'#!/bin/sh' \
	'set -eu' \
	'test "$*" = "test ./cmd/punarod -run ^TestRunFailsClosedBeforeStartingAttachmentRuntime$ -count=1"' \
	': > "$PUNARO_RELEASE_GATES_GO_MARKER"' \
	>"$release_gate_fixture/bin/go"
chmod +x "$release_gate_fixture/bin/go" "$release_gate_fixture/verify-release-gates.sh"

printf '%s\n' \
	'# Core personal self-hosted evidence' \
	'' \
	'- **Decision:** approved for core personal self-hosted use.' \
	'- **Gated capabilities:** withheld.' \
	>"$release_gate_fixture/docs/release-evidence/core.md"
printf '%s\n' \
	'# Security release gates' \
	'' \
	'- [ ] Trusted-relay attachments remain closed.' \
	'- [ ] Public relay remains closed.' \
	>"$release_gate_fixture/docs/security-release-gates.md"

release_gate_marker="$release_gate_fixture/go-called"
(
	cd "$release_gate_fixture"
	PATH="$release_gate_fixture/bin:$PATH" \
		PUNARO_RELEASE_GATES_GO_MARKER="$release_gate_marker" \
		./verify-release-gates.sh
)
test -f "$release_gate_marker"

rm "$release_gate_marker"
printf '%s\n' \
	'# Security release gates' \
	'' \
	'- [x] Trusted-relay attachments are open.' \
	'- [ ] Public relay remains closed.' \
	>"$release_gate_fixture/docs/security-release-gates.md"

if (
	cd "$release_gate_fixture"
	PATH="$release_gate_fixture/bin:$PATH" \
		PUNARO_RELEASE_GATES_GO_MARKER="$release_gate_marker" \
		./verify-release-gates.sh
) >/dev/null 2>&1; then
	printf '%s\n' 'release gate verifier accepted checked gated-runtime authority' >&2
	exit 1
fi
test ! -e "$release_gate_marker"

printf '%s\n' release_gate_tests_passed
