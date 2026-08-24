#!/bin/sh
set -eu

state=$PUNARO_FAKE_GH_STATE
remote="$state/remote"
printf '%s\n' "$*" >>"$PUNARO_FAKE_GH_LOG"

copy_assets() {
	tag=$1
	destination=$2
	mkdir -p "$destination"
	for source in "$remote/$tag"/*; do
		[ -f "$source" ] && cp "$source" "$destination/"
	done
}

[ "$1" = release ] || exit 2
operation=$2
tag=$3
shift 3

case "$operation" in
	view)
		if [ "$tag" = catalog ]; then
			[ -d "$remote/catalog" ] || exit 1
			assets='[]'
			if [ -f "$remote/catalog/punaro-catalog.previous.json" ] && [ -f "$remote/catalog/punaro-catalog.previous.sig" ]; then
				assets='[{"name":"punaro-catalog.previous.json"},{"name":"punaro-catalog.previous.sig"}]'
			elif [ -f "$remote/catalog/punaro-catalog.previous.json" ]; then
				assets='[{"name":"punaro-catalog.previous.json"}]'
			elif [ -f "$remote/catalog/punaro-catalog.previous.sig" ]; then
				assets='[{"name":"punaro-catalog.previous.sig"}]'
			fi
			printf '{"isDraft":%s,"assets":%s}\n' "$(cat "$state/catalog-draft")" "$assets"
		else
			printf '{"tagName":"%s","isDraft":%s,"isPrerelease":%s}\n' \
				"$tag" "$(cat "$state/release-draft")" "$(cat "$state/release-prerelease")"
		fi
		;;
	download)
		destination=
		while [ "$#" -gt 0 ]; do
			if [ "$1" = --dir ]; then
				destination=$2
				shift 2
			else
				shift
			fi
		done
		[ -n "$destination" ] || exit 2
		if [ "$tag" = catalog ] && [ -f "$state/fail-catalog-download-once" ]; then
			rm "$state/fail-catalog-download-once"
			exit 1
		fi
		copy_assets "$tag" "$destination"
		;;
	upload)
		mkdir -p "$remote/$tag"
		for source in "$@"; do
			if [ -f "$source" ]; then
				asset=$(basename -- "$source")
				if [ "$tag" = catalog ] && [ "$(cat "$state/catalog-draft")" = false ] && { [ "$asset" = punaro-catalog.json ] || [ "$asset" = punaro-catalog.sig ]; }; then
					touch "$state/unsafe-live-catalog-upload"
				fi
				cp "$source" "$remote/$tag/"
			fi
		done
		;;
	create)
		mkdir -p "$remote/$tag"
		printf '%s\n' true >"$state/catalog-draft"
		for source in "$@"; do
			if [ -f "$source" ]; then
				cp "$source" "$remote/$tag/"
			fi
		done
		;;
	edit)
		for argument in "$@"; do
			case "$argument" in
				--draft=true)
					if [ "$tag" = catalog ]; then printf '%s\n' true >"$state/catalog-draft"; else printf '%s\n' true >"$state/release-draft"; fi
					;;
				--draft=false)
					if [ "$tag" = catalog ]; then printf '%s\n' false >"$state/catalog-draft"; else printf '%s\n' false >"$state/release-draft"; fi
					;;
				--prerelease)
					[ "$tag" = catalog ] || printf '%s\n' true >"$state/release-prerelease"
					;;
			esac
		done
		;;
	*) exit 2 ;;
esac
