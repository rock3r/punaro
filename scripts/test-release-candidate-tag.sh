#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
generator="$repo_dir/scripts/release-candidate-tag.sh"

sha=ffffffffffffffffffffffffffffffffffffffff
run_id=18446744073709551615
attempt=4294967295
expected="candidate-$sha-$run_id-$attempt"

actual=$($generator "$sha" "$run_id" "$attempt")
[ "$actual" = "$expected" ] || {
	printf '%s\n' 'release candidate tag is not deterministic' >&2
	exit 1
}
[ "${#actual}" -le 128 ] || {
	printf '%s\n' 'release candidate tag exceeds the Docker limit' >&2
	exit 1
}
printf '%s\n' "$actual" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$' || {
	printf '%s\n' 'release candidate tag is not Docker-compatible' >&2
	exit 1
}

next=$($generator "$sha" "$run_id" 2)
[ "$next" != "$actual" ] || {
	printf '%s\n' 'release candidate tag does not distinguish workflow attempts' >&2
	exit 1
}

if "$generator" "$sha" "$(printf '%0130d' 1)" 1 >/dev/null 2>&1; then
	printf '%s\n' 'release candidate tag generator accepted an oversized tag' >&2
	exit 1
fi
if "$generator" invalid-sha 1 1 >/dev/null 2>&1; then
	printf '%s\n' 'release candidate tag generator accepted an invalid commit SHA' >&2
	exit 1
fi
if "$generator" "$sha" run 1 >/dev/null 2>&1; then
	printf '%s\n' 'release candidate tag generator accepted an invalid run ID' >&2
	exit 1
fi
if "$generator" "$sha" 1 attempt >/dev/null 2>&1; then
	printf '%s\n' 'release candidate tag generator accepted an invalid attempt' >&2
	exit 1
fi
if "$generator" "$sha" 1 1 unexpected >/dev/null 2>&1; then
	printf '%s\n' 'release candidate tag generator accepted an unexpected release-name argument' >&2
	exit 1
fi
