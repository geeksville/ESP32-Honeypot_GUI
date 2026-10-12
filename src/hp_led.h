// Status LED — tells you at a glance whether the trap is being poked.
//
// Two backends, chosen at build time:
//   HP_STATUS_LED_RGB == 1 : a single WS2812/NeoPixel —
//       breathing yellow : not on the Wi-Fi network (unconfigured, or link down)
//       breathing green  : on Wi-Fi, no SEV_ALERT events since boot (or since stats cleared)
//       blinking red     : at least one alert — credential theft, dropper URL, ...
//   HP_STATUS_LED_RGB == 0 : a plain GPIO driven with hardware PWM (LEDC) —
//       off           : not on the Wi-Fi network
//       dim breathing : on Wi-Fi, no alerts
//       bright blink  : at least one alert
//
// The pin is chosen at build time with -DHP_STATUS_LED_PIN=<gpio>. Boards
// without the flag (e.g. esp32dev) compile this module to a no-op, so the
// firmware still builds and runs on hardware with no LED wired up.
//
// If the LED is wired 3.3V -> LED -> pin (active low, like the XIAO ESP32S3
// user LED on GPIO 21), also pass -DHP_STATUS_LED_ACTIVE_LOW=1; the GPIO
// backend inverts the PWM duty so the states still read as documented above.
#pragma once
#include <Arduino.h>

// Constructs the pixel driver. Safe to call once from setup().
void ledBegin();

// Advances the animation. Call from a low-priority task at ~30 ms cadence.
void ledPump();

// Reports whether the station is currently joined to the configured network.
// The LED uses this to breathe yellow while the link is down or unconfigured.
bool ledWifiUp();
