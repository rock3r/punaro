#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

make -C "$root" --no-print-directory canopi-binaries \
  CANOPI_OUTPUT="$fixture/collector/canopi" \
  CANOPI_CLAUDE_HOOK_OUTPUT="$fixture/adapter/canopi-claude-hook" \
  CANOPI_SIM_OUTPUT="$fixture/simulator/canopi-sim"

test -x "$fixture/collector/canopi"
test -x "$fixture/adapter/canopi-claude-hook"
test -x "$fixture/simulator/canopi-sim"
printf '%s\n' canopi_binary_output_tests_passed
