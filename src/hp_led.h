// Status LED — a single WS2812/NeoPixel that tells you at a glance whether the
// trap is being poked.
//
//   breathing yellow : not on the Wi-Fi network (unconfigured, or link down)
//   breathing green  : on Wi-Fi, no SEV_ALERT events since boot (or since stats cleared)
//   blinking red     : at least one alert — credential theft, dropper URL, ...
//
// The pin is chosen at build time with -DHP_STATUS_LED_PIN=<gpio>. Boards
// without the flag (e.g. esp32dev) compile this module to a no-op, so the
// firmware still builds and runs on hardware with no LED wired up.
#pragma once
#include <Arduino.h>

// Constructs the pixel driver. Safe to call once from setup().
void ledBegin();

// Advances the animation. Call from a low-priority task at ~30 ms cadence.
void ledPump();

// Reports whether the station is currently joined to the configured network.
// The LED uses this to breathe yellow while the link is down or unconfigured.
bool ledWifiUp();
