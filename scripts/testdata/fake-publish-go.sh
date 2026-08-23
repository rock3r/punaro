#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$PUNARO_FAKE_GO_LOG"
case " $* " in
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
