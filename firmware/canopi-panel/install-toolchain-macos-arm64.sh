#!/bin/sh
set -eu

archive_name="riscv32-esp-elf-gcc8_4_0-esp-2021r2-patch5-macos-arm64.tar.gz"
archive_sha256="6e03f2ab1f145be13f8890c6de77b53f52c7bffe3d9d5824549db20298f5ba91"
archive_url="https://github.com/espressif/crosstool-NG/releases/download/esp-2021r2-patch5/${archive_name}"
openocd_archive_name="openocd-esp32-macos-arm64-0.12.0-esp32-20260703.tar.gz"
openocd_archive_sha256="fe366c8b72fc287fbdf5d62a1178dd882c37dc4a5c29205f126a6c3125aa9f41"
openocd_archive_url="https://github.com/espressif/openocd-esp32/releases/download/v0.12.0-esp32-20260703/${openocd_archive_name}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
toolchain_dir="${script_dir}/.toolchains/gcc8-arm64"
compiler="${toolchain_dir}/bin/riscv32-esp-elf-gcc"
openocd_dir="${script_dir}/.toolchains/openocd-arm64"
openocd="${openocd_dir}/bin/openocd"

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  echo "This installer is only for Apple Silicon macOS." >&2
  exit 2
fi

temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/canopi-toolchain.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

mkdir -p "${script_dir}/.toolchains"

if [ -x "$compiler" ]; then
  :
elif [ -e "$toolchain_dir" ]; then
  echo "Incomplete toolchain directory exists: $toolchain_dir" >&2
  echo "Move it aside, then rerun this installer." >&2
  exit 2
else
  curl -fL --retry 3 --output "${temporary_dir}/${archive_name}" "$archive_url"
  printf '%s  %s\n' "$archive_sha256" "${temporary_dir}/${archive_name}" |
    shasum -a 256 -c -
  mkdir -p "${temporary_dir}/toolchain"
  tar -xzf "${temporary_dir}/${archive_name}" \
    --strip-components=1 -C "${temporary_dir}/toolchain"
  cp "${script_dir}/toolchain-package.json" "${temporary_dir}/toolchain/package.json"
  mv "${temporary_dir}/toolchain" "$toolchain_dir"
fi

if [ -x "$openocd" ]; then
  :
elif [ -e "$openocd_dir" ]; then
  echo "Incomplete OpenOCD directory exists: $openocd_dir" >&2
  echo "Move it aside, then rerun this installer." >&2
  exit 2
else
  curl -fL --retry 3 --output "${temporary_dir}/${openocd_archive_name}" "$openocd_archive_url"
  printf '%s  %s\n' "$openocd_archive_sha256" "${temporary_dir}/${openocd_archive_name}" |
    shasum -a 256 -c -
  mkdir -p "${temporary_dir}/openocd"
  tar -xzf "${temporary_dir}/${openocd_archive_name}" \
    --strip-components=1 -C "${temporary_dir}/openocd"
  cp "${script_dir}/openocd-package.json" "${temporary_dir}/openocd/package.json"
  mv "${temporary_dir}/openocd" "$openocd_dir"
fi

"$compiler" --version | sed -n '1p'
"$openocd" --version 2>&1 | sed -n '1p'
