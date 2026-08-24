#pragma once

#define CANOPI_WIFI_SSID "replace-me"
#define CANOPI_WIFI_PASSWORD "replace-me"
#define CANOPI_RENDER_URL "https://canopi.example.internal:8443/v1/render/800x480.png"
#define CANOPI_TOKEN "replace-with-the-same-bearer-token-as-the-server"
static constexpr char CANOPI_TLS_CA_CERT[] = R"CANOPI_CA(
-----BEGIN CERTIFICATE-----
replace-with-the-PEM-encoded-CA-that-issued-the-collector-certificate
-----END CERTIFICATE-----
)CANOPI_CA";

// USB-powered default. For battery operation, uncomment both lines; the panel
// will deep-sleep for three minutes between conditional fetches.
// #define CANOPI_BATTERY_MODE
// #define CANOPI_BATTERY_SLEEP_SECONDS 180
