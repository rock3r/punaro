#!/bin/sh
# Compatibility-preserving public entry point for per-machine adapter setup.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$script_dir/install-adapter.sh" "$@"
