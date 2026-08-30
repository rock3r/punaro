#!/bin/sh
set -eu

state=$PUNARO_FAKE_GH_STATE
log=${PUNARO_FAKE_CURL_LOG:-/dev/null}
printf '%s\n' "$*" >>"$log"

output=
url=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--output|--connect-timeout|--max-time|--proto)
			[ "$#" -ge 2 ] || exit 2
			[ "$1" = --output ] && output=$2
			shift 2
			;;
		--fail|--silent|--show-error|--location|--tlsv1.2)
			shift
			;;
		*)
			url=$1
			shift
			;;
	esac
done

[ -n "$output" ] && [ -n "$url" ] || exit 2
prefix=https://github.com/rock3r/punaro/releases/download/
case "$url" in "$prefix"*) ;; *) exit 2 ;; esac
relative=${url#"$prefix"}
tag=${relative%%/*}
asset=${relative#*/}
[ -n "$tag" ] && [ -n "$asset" ] && [ "$asset" != "$relative" ] || exit 2
case "$asset" in */*) exit 2 ;; esac

if [ -f "$state/fail-public-origin-once" ]; then
	rm "$state/fail-public-origin-once"
	exit 1
fi
source=$state/remote/$tag/$asset
[ -f "$source" ] || exit 1
cp "$source" "$output"
