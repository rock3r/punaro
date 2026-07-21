#!/bin/sh
# Kept as an explicit tombstone so old automation fails closed instead of
# silently leaving a partially configured legacy attachment runtime.
set -eu

printf '%s\n' 'attachment v3 relay configuration is retired; remove legacy attachment settings and use PUNARO_TRUSTED_ATTACHMENTS_ENABLED with punaro-trusted-attachment' >&2
exit 2
