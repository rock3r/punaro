#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$PUNARO_FAKE_GO_LOG"
case " $* " in
	*' verify-artifacts '*)
		directory=
		while [ "$#" -gt 0 ]; do
			if [ "$1" = --dir ]; then
				directory=$2
				shift 2
			else
				shift
			fi
		done
		[ -n "$directory" ] && [ "$(cat "$directory/punaro-adapter-linux-amd64" 2>/dev/null)" = artifact ] || exit 2
		;;
	*' publication-check '*)
		if [ -f "$PUNARO_FAKE_GH_STATE/fail-publication-check" ]; then
			exit 2
		fi
		if [ -f "$PUNARO_FAKE_GH_STATE/fail-previous-publication-check" ]; then
			case " $* " in *' --previous-catalog '*) exit 2 ;; esac
		fi
		;;
esac
exit 0
