#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runner="$root/scripts/production-compose"
temporary=$(mktemp -d)
cleanup() { rm -rf "$temporary"; }
trap cleanup EXIT INT TERM

fakebin="$temporary/bin"
mkdir -p "$fakebin"
cat >"$fakebin/docker" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >"${PUNARO_TEST_DOCKER_ARGS:?}"
SH
chmod 700 "$fakebin/docker"

owner_password="$temporary/owner-password"
app_password="$temporary/app-password"
app_dsn="$temporary/app.dsn"
printf '%s\n' 'owner-password' >"$owner_password"
printf '%s\n' 'app-password' >"$app_password"
printf '%s\n' 'postgres://punaro_app:app-password@127.0.0.1:5432/punaro?sslmode=disable' >"$app_dsn"
chmod 600 "$owner_password" "$app_password" "$app_dsn"

base_env() {
  export PATH="$fakebin:$PATH"
  export PUNARO_TEST_DOCKER_ARGS="$temporary/docker-args"
  export PUNARO_IMAGE='example.invalid/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  export PUNARO_RUNTIME_UID=1000
  export PUNARO_RUNTIME_GID=1000
  export PUNARO_COMPOSE_PROJECT_NAME='punaro-production-test'
  export PUNARO_PUBLIC_URL='https://punaro.example'
  export PUNARO_POSTGRES_OWNER_PASSWORD_FILE="$owner_password"
  export PUNARO_POSTGRES_APP_PASSWORD_FILE="$app_password"
  export PUNARO_POSTGRES_APP_DSN_FILE="$app_dsn"
}

base_env
"$runner" config
grep -Fqx "compose --project-name punaro-production-test -f $root/deploy/compose/production.yaml config" "$temporary/docker-args"

base_env
PUNARO_IMAGE='example.invalid/punaro:latest'
if "$runner" config >/dev/null 2>&1; then
  echo 'production runner accepted an unpinned image' >&2
  exit 1
fi

base_env
PUNARO_COMPOSE_PROJECT_NAME='unsafe/name'
if "$runner" config >/dev/null 2>&1; then
	echo 'production runner accepted an unsafe Compose project name' >&2
	exit 1
fi

base_env
PUNARO_COMPOSE_PROJECT_NAME='-punaro-production-test'
if "$runner" config >/dev/null 2>&1; then
	echo 'production runner accepted a Compose project name with an invalid leading character' >&2
	exit 1
fi

base_env
PUNARO_IMAGE='example.invalid/punaro:release@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
if "$runner" config >/dev/null 2>&1; then
  echo 'production runner accepted an image that punaro init rejects' >&2
  exit 1
fi

base_env
PUNARO_IMAGE='example.invalid/foo..bar@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
if "$runner" config >/dev/null 2>&1; then
	echo 'production runner accepted an image repository that punaro init rejects' >&2
	exit 1
fi

base_env
PUNARO_RUNTIME_UID=0
if "$runner" config >/dev/null 2>&1; then
  echo 'production runner accepted root runtime UID' >&2
  exit 1
fi
