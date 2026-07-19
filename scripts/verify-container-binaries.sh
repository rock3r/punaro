#!/bin/sh
set -eu

dockerfile=${1:-Dockerfile}

for binary in punarod punaro-migrate punaro-adapter punaro-directory punaro-telegram punaro-attachment; do
	if ! grep -Fq -- "-o /out/$binary ./cmd/$binary" "$dockerfile"; then
		echo "container build does not produce $binary" >&2
		exit 1
	fi
	if ! grep -Fq -- "/out/$binary /usr/local/bin/$binary" "$dockerfile"; then
		echo "container runtime does not include $binary" >&2
		exit 1
	fi
done
