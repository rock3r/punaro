#include <Arduino.h>
#include <HTTPClient.h>
#include <PNGdec.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <memory>
#include <time.h>

#include "driver.h"
#include "secrets.h"
#include <TFT_eSPI.h>

namespace {

constexpr int CANOPI_WIDTH = 800;
constexpr int CANOPI_HEIGHT = 480;
constexpr int MAX_PNG_BYTES = 256 * 1024;
constexpr uint32_t POLL_INTERVAL_MS = 20000;
constexpr uint32_t WIFI_TIMEOUT_MS = 15000;
constexpr uint32_t DOWNLOAD_TIMEOUT_MS = 7000;
constexpr uint32_t CLOCK_TIMEOUT_MS = 15000;
constexpr uint32_t ETAG_CACHE_VERSION = 2;
constexpr time_t VALID_CLOCK_AFTER = 1704067200;

EPaper epaper;
PNG png;
uint16_t scanline[CANOPI_WIDTH];
alignas(uint16_t) uint8_t packedScanline[CANOPI_WIDTH / 8];
RTC_DATA_ATTR char lastETag[80] = "";
RTC_DATA_ATTR uint32_t lastETagVersion = 0;

bool rgb565IsWhite(uint16_t pixel) {
  const uint32_t red = ((pixel >> 11) & 0x1f) * 255 / 31;
  const uint32_t green = ((pixel >> 5) & 0x3f) * 255 / 63;
  const uint32_t blue = (pixel & 0x1f) * 255 / 31;
  return red * 299 + green * 587 + blue * 114 >= 128000;
}

int drawPNGLine(PNGDRAW *line) {
  if (line->y < 0 || line->y >= CANOPI_HEIGHT || line->iWidth != CANOPI_WIDTH) {
    return 0;
  }
  png.getLineAsRGB565(line, scanline, PNG_RGB565_LITTLE_ENDIAN, 0xffffffff);
  memset(packedScanline, 0, sizeof(packedScanline));
  for (int x = 0; x < CANOPI_WIDTH; ++x) {
    if (rgb565IsWhite(scanline[x])) {
      packedScanline[x >> 3] |= static_cast<uint8_t>(0x80U >> (x & 7));
    }
  }
  // EPaper is a one-bit TFT_eSprite. Its pushImage overload takes a uint16_t
  // pointer even when the source is a packed, MSB-first one-bit bitmap.
  epaper.pushImage(0, line->y, CANOPI_WIDTH, 1,
                   reinterpret_cast<uint16_t *>(packedScanline));
  return 1;
}

bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }
  Serial.println("Canopi: connecting to Wi-Fi");
  WiFi.mode(WIFI_STA);
  WiFi.begin(CANOPI_WIFI_SSID, CANOPI_WIFI_PASSWORD);
  const uint32_t started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < WIFI_TIMEOUT_MS) {
    delay(100);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("Canopi: Wi-Fi timeout (status=%d)\n", WiFi.status());
    return false;
  }
  Serial.printf("Canopi: Wi-Fi connected, IP=%s\n",
                WiFi.localIP().toString().c_str());
  return true;
}

bool syncClock() {
  if (time(nullptr) >= VALID_CLOCK_AFTER) {
    return true;
  }
  Serial.println("Canopi: synchronizing clock for TLS");
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  const uint32_t started = millis();
  while (time(nullptr) < VALID_CLOCK_AFTER &&
         millis() - started < CLOCK_TIMEOUT_MS) {
    delay(100);
  }
  if (time(nullptr) < VALID_CLOCK_AFTER) {
    Serial.println("Canopi: clock synchronization timed out");
    return false;
  }
  Serial.println("Canopi: clock synchronized");
  return true;
}

bool readExact(WiFiClient *stream, uint8_t *target, size_t length) {
  size_t read = 0;
  const uint32_t started = millis();
  while (read < length && millis() - started < DOWNLOAD_TIMEOUT_MS) {
    const int available = stream->available();
    if (available <= 0) {
      delay(5);
      continue;
    }
    const size_t remaining = length - read;
    const size_t availableBytes = static_cast<size_t>(available);
    const size_t requested = remaining < availableBytes ? remaining : availableBytes;
    const size_t chunk = stream->readBytes(target + read, requested);
    if (chunk == 0) {
      return false;
    }
    read += chunk;
  }
  return read == length;
}

bool refreshOnce() {
  if (!connectWiFi()) {
    return false;
  }
  if (!syncClock()) {
    return false;
  }

  const String renderURL = CANOPI_RENDER_URL;
  if (!renderURL.startsWith("https://")) {
    Serial.println("Canopi: refusing plaintext render URL");
    return false;
  }
  WiFiClientSecure transport;
  transport.setCACert(CANOPI_TLS_CA_CERT);
  HTTPClient http;
  http.setTimeout(DOWNLOAD_TIMEOUT_MS);
  const char *responseHeaders[] = {"ETag", "Content-Type"};
  http.collectHeaders(responseHeaders, 2);
  if (!http.begin(transport, renderURL)) {
    Serial.println("Canopi: render request setup failed");
    return false;
  }
  http.addHeader("Authorization", String("Bearer ") + CANOPI_TOKEN);
  if (lastETag[0] != '\0') {
    http.addHeader("If-None-Match", lastETag);
  }

  const int status = http.GET();
  if (status == HTTP_CODE_NOT_MODIFIED) {
    Serial.println("Canopi: render unchanged (304)");
    http.end();
    return false;
  }
  if (status != HTTP_CODE_OK) {
    Serial.printf("Canopi: render request failed (HTTP %d)\n", status);
    http.end();
    return false;
  }

  const String contentType = http.header("Content-Type");
  const int contentLength = http.getSize();
  const String nextETag = http.header("ETag");
  if (!contentType.startsWith("image/png") || contentLength <= 0 ||
      contentLength > MAX_PNG_BYTES || nextETag.length() < 2 ||
      nextETag.length() >= sizeof(lastETag)) {
    Serial.printf("Canopi: invalid render metadata (bytes=%d, etag=%u)\n",
                  contentLength, static_cast<unsigned>(nextETag.length()));
    http.end();
    return false;
  }

  std::unique_ptr<uint8_t[]> payload(new (std::nothrow) uint8_t[contentLength]);
  if (!payload || !readExact(http.getStreamPtr(), payload.get(), contentLength)) {
    Serial.println("Canopi: render download incomplete");
    http.end();
    return false;
  }
  http.end();

  const int opened = png.openRAM(payload.get(), contentLength, drawPNGLine);
  if (opened != PNG_SUCCESS) {
    Serial.printf("Canopi: PNG open failed (%d)\n", opened);
    return false;
  }
  if (png.getWidth() != CANOPI_WIDTH || png.getHeight() != CANOPI_HEIGHT) {
    Serial.printf("Canopi: PNG geometry invalid (%dx%d)\n", png.getWidth(),
                  png.getHeight());
    png.close();
    return false;
  }

  epaper.fillScreen(TFT_WHITE);
  const int decoded = png.decode(nullptr, 0);
  png.close();
  if (decoded != PNG_SUCCESS) {
    Serial.printf("Canopi: PNG decode failed (%d)\n", decoded);
    return false;
  }
  epaper.update();
  nextETag.toCharArray(lastETag, sizeof(lastETag));
  Serial.printf("Canopi: display refreshed (%d bytes)\n", contentLength);
  return true;
}

void sleepIfConfigured() {
#ifdef CANOPI_BATTERY_MODE
#ifndef CANOPI_BATTERY_SLEEP_SECONDS
#define CANOPI_BATTERY_SLEEP_SECONDS 180
#endif
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  esp_sleep_enable_timer_wakeup(
      static_cast<uint64_t>(CANOPI_BATTERY_SLEEP_SECONDS) * 1000000ULL);
  esp_deep_sleep_start();
#endif
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(250);
  Serial.println("Canopi: starting");
  epaper.begin();
  epaper.setRotation(0);
  Serial.printf("Canopi: panel geometry %dx%d\n", epaper.width(),
                epaper.height());
  if (epaper.width() != CANOPI_WIDTH || epaper.height() != CANOPI_HEIGHT) {
    Serial.println("Canopi: unexpected panel geometry");
    return;
  }
  if (lastETagVersion != ETAG_CACHE_VERSION) {
    lastETag[0] = '\0';
    lastETagVersion = ETAG_CACHE_VERSION;
    Serial.println("Canopi: display cache invalidated after firmware update");
  }
  (void)refreshOnce();
  sleepIfConfigured();
}

void loop() {
  delay(POLL_INTERVAL_MS);
  (void)refreshOnce();
}
