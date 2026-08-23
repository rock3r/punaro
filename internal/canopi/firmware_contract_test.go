// Package canopi tests the server and panel-client contract together.
package canopi

import (
	"os"
	"strings"
	"testing"
)

func TestPanelFirmwareContractUsesConditionalValidatedRefresh(t *testing.T) {
	payload, err := os.ReadFile("../../firmware/canopi-panel/src/main.cpp")
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	for _, required := range []string{"If-None-Match", "ETag", "HTTP_CODE_NOT_MODIFIED", "image/png", "CANOPI_WIDTH = 800", "CANOPI_HEIGHT = 480", "int drawPNGLine(PNGDRAW *line)", "PNG_RGB565_LITTLE_ENDIAN", "packedScanline[CANOPI_WIDTH / 8]", "0x80U >> (x & 7)", "reinterpret_cast<uint16_t *>(packedScanline)", "ETAG_CACHE_VERSION", "lastETagVersion != ETAG_CACHE_VERSION", "lastETag[0] = '\\0'", "startsWith(\"https://\")", "configTime(", "time(nullptr)", "if (!syncClock())", "setCACert(CANOPI_TLS_CA_CERT)", "epaper.update()"} {
		if !strings.Contains(source, required) {
			t.Errorf("panel firmware is missing %q", required)
		}
	}
	if strings.Index(source, "if (!syncClock())") > strings.Index(source, "setCACert(CANOPI_TLS_CA_CERT)") {
		t.Fatal("panel validates TLS before establishing a valid wall clock")
	}
	if strings.Contains(source, "pushImage(0, line->y, CANOPI_WIDTH, 1, scanline)") {
		t.Fatal("panel firmware passes RGB565 bytes directly to its one-bit sprite")
	}
	if notModified, refresh := strings.Index(source, "HTTP_CODE_NOT_MODIFIED"), strings.Index(source, "epaper.update()"); notModified < 0 || refresh < 0 || notModified > refresh {
		t.Fatal("panel firmware does not handle 304 before its display refresh path")
	}
	example, err := os.ReadFile("../../firmware/canopi-panel/include/secrets.example.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(example), `CANOPI_RENDER_URL "https://`) || !strings.Contains(string(example), "CANOPI_TLS_CA_CERT") {
		t.Fatal("panel firmware example does not require an HTTPS URL and trusted CA")
	}
}

func TestPanelFirmwarePinsArduinoCompatibleNativeToolchain(t *testing.T) {
	payload, err := os.ReadFile("../../firmware/canopi-panel/platformio.ini")
	if err != nil {
		t.Fatal(err)
	}
	configuration := string(payload)
	for _, required := range []string{
		"toolchain-riscv32-esp@symlink://${PROJECT_DIR}/.toolchains/gcc8-arm64",
		"tool-openocd-esp32@symlink://${PROJECT_DIR}/.toolchains/openocd-arm64",
		"-march=rv32imc",
		"pre:configure_toolchain.py",
		"post:configure_upload.py",
	} {
		if !strings.Contains(configuration, required) {
			t.Fatalf("panel firmware toolchain configuration is missing %q", required)
		}
	}
	toolchainConfig, err := os.ReadFile("../../firmware/canopi-panel/configure_toolchain.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"-Xassembler", "-misa-spec=2.2", "ASPPFLAGS"} {
		if !strings.Contains(string(toolchainConfig), required) {
			t.Fatalf("panel firmware assembler configuration is missing %q", required)
		}
	}
	uploadConfig, err := os.ReadFile("../../firmware/canopi-panel/configure_upload.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"UPLOADERFLAGS", `.replace("{{", "{")`, `.replace("}}", "}")`} {
		if !strings.Contains(string(uploadConfig), required) {
			t.Fatalf("panel firmware upload configuration is missing %q", required)
		}
	}
	if strings.Contains(configuration, "12.2.0+20230208") {
		t.Fatal("GCC 12 libgcc emits unsupported floating-point CSR instructions on ESP32-C3")
	}

	installer, err := os.ReadFile("../../firmware/canopi-panel/install-toolchain-macos-arm64.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"riscv32-esp-elf-gcc8_4_0-esp-2021r2-patch5-macos-arm64.tar.gz",
		"6e03f2ab1f145be13f8890c6de77b53f52c7bffe3d9d5824549db20298f5ba91",
		"openocd-esp32-macos-arm64-0.12.0-esp32-20260703.tar.gz",
		"fe366c8b72fc287fbdf5d62a1178dd882c37dc4a5c29205f126a6c3125aa9f41",
		"shasum -a 256 -c",
	} {
		if !strings.Contains(string(installer), required) {
			t.Fatalf("panel firmware toolchain installer is missing %q", required)
		}
	}
}
