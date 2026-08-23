#pragma once

#define CANOPI_WIFI_SSID "replace-me"
#define CANOPI_WIFI_PASSWORD "replace-me"
#define CANOPI_RENDER_URL "http://10.0.0.20:8090/v1/render/800x480.png"
#define CANOPI_TOKEN "replace-with-the-same-bearer-token-as-the-server"

// USB-powered default. For battery operation, uncomment both lines; the panel
// will deep-sleep for three minutes between conditional fetches.
// #define CANOPI_BATTERY_MODE
// #define CANOPI_BATTERY_SLEEP_SECONDS 180
