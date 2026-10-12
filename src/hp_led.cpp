// Status LED implementation. See hp_led.h for the contract.
//
// Two backends, chosen at build time:
//   HP_STATUS_LED_RGB == 1 : Adafruit NeoPixel (WS2812) — breathing green,
//                            breathing yellow, blinking red.
//   HP_STATUS_LED_RGB == 0 : plain GPIO driven with hardware PWM (LEDC) —
//                            dim breathing when healthy, bright blink on alert.
#include "hp_led.h"
#include "hp_events.h"
#include "hp_config.h"

#if defined(HP_STATUS_LED_PIN)

#include <WiFi.h>

// The station is "up" only when it is actually joined to the configured
// network. Unconfigured (no SSID) or a dropped link both read as down, which
// is exactly the state the operator needs the LED to flag.
bool ledWifiUp() {
  return g_cfg.ssid[0] && WiFi.status() == WL_CONNECTED;
}

#if defined(HP_STATUS_LED_RGB) && HP_STATUS_LED_RGB == 1

// ---- NeoPixel backend -----------------------------------------------------
// Adafruit NeoPixel drives WS2812/WS2812B pixels over the ESP32's RMT
// peripheral — no bit-banging, no interrupts to babysit.
#include <Adafruit_NeoPixel.h>

// One pixel, GRB order (the WS2812 default), NEO_KHZ800 signalling.
static Adafruit_NeoPixel s_px(1, HP_STATUS_LED_PIN, NEO_GRB + NEO_KHZ800);

// Breathing: brightness follows a sine wave between these bounds.
static const uint8_t  BREATH_MIN = 2;
static const uint8_t  BREATH_MAX = 30;
static const uint32_t BREATH_PERIOD_MS = 2600;   // one full in-out cycle

// Blink: full red for this long, then off, repeating.
static const uint32_t BLINK_ON_MS  = 250;
static const uint32_t BLINK_OFF_MS = 250;

static uint32_t s_lastMs = 0;
static bool     s_alert  = false;
static bool     s_wifiUp = false;

void ledBegin() {
  s_px.begin();
  s_px.setBrightness(255);   // we scale the colour ourselves
  s_px.clear();
  s_px.show();
  Serial.printf("[led] status LED on GPIO %d\n", HP_STATUS_LED_PIN);
}

void ledPump() {
  uint32_t now = millis();
  if (now - s_lastMs < 30) return;   // ~30 ms frame cadence
  s_lastMs = now;

  bool alert = evAlertCount() > 0;
  bool wifiUp = ledWifiUp();
  if (alert != s_alert || wifiUp != s_wifiUp) {
    s_alert  = alert;
    s_wifiUp = wifiUp;
    if (alert) {
      Serial.println("[led] alert — blinking red");
    } else if (!wifiUp) {
      Serial.println("[led] no Wi-Fi — breathing yellow");
    } else {
      Serial.println("[led] clear — breathing green");
    }
  }

  if (s_alert) {
    // 1 Hz blink: 250 ms on, 250 ms off.
    uint32_t phase = now % (BLINK_ON_MS + BLINK_OFF_MS);
    if (phase < BLINK_ON_MS) s_px.setPixelColor(0, s_px.Color(255, 0, 0));
    else                     s_px.clear();
  } else if (!s_wifiUp) {
    // Breathing yellow. Same sine as green, but R+G so it reads as amber.
    float t = (float)(now % BREATH_PERIOD_MS) / BREATH_PERIOD_MS;
    float b = BREATH_MIN + (BREATH_MAX - BREATH_MIN) * (0.5f + 0.5f * sinf(2.0f * PI * t));
    s_px.setPixelColor(0, s_px.Color((uint8_t)b, (uint8_t)b, 0));
  } else {
    // Breathing green. sin() over a 2.6 s period, mapped to [BREATH_MIN, BREATH_MAX].
    float t = (float)(now % BREATH_PERIOD_MS) / BREATH_PERIOD_MS;
    float b = BREATH_MIN + (BREATH_MAX - BREATH_MIN) * (0.5f + 0.5f * sinf(2.0f * PI * t));
    s_px.setPixelColor(0, s_px.Color(0, (uint8_t)b, 0));
  }

  s_px.show();
}

#else

// ---- Plain GPIO backend ---------------------------------------------------
// No colour, so the states collapse to brightness:
//   off           : not on Wi-Fi (unconfigured, or link down)
//   dim breathing : on Wi-Fi, no alerts
//   bright blink  : at least one alert
// analogWrite() on the ESP32 maps to the LEDC peripheral — true hardware PWM.
// Some boards (e.g. the XIAO ESP32S3 user LED on GPIO 21) wire the LED from
// 3.3V through to the pin, so the logic is active-low: high duty = off, and a
// plain '0' is fully on. HP_STATUS_LED_ACTIVE_LOW inverts the duty so the
// states above read correctly.
#if defined(HP_STATUS_LED_ACTIVE_LOW) && HP_STATUS_LED_ACTIVE_LOW == 1
static inline int ledDuty(int duty) { return 255 - duty; }
#else
static inline int ledDuty(int duty) { return duty; }
#endif

static const uint8_t  BREATH_MIN = 20;
static const uint8_t  BREATH_MAX = 60;
static const uint32_t BREATH_PERIOD_MS = 2600;   // one full in-out cycle

// Blink: full brightness for this long, then off, repeating.
static const uint32_t BLINK_ON_MS  = 250;
static const uint32_t BLINK_OFF_MS = 250;

static uint32_t s_lastMs = 0;
static bool     s_alert  = false;
static bool     s_wifiUp = false;

void ledBegin() {
  analogWrite(HP_STATUS_LED_PIN, ledDuty(0));
  Serial.printf("[led] status LED on GPIO %d (PWM)\n", HP_STATUS_LED_PIN);
}

void ledPump() {
  uint32_t now = millis();
  if (now - s_lastMs < 30) return;   // ~30 ms frame cadence
  s_lastMs = now;

  bool alert = evAlertCount() > 0;
  bool wifiUp = ledWifiUp();
  if (alert != s_alert || wifiUp != s_wifiUp) {
    s_alert  = alert;
    s_wifiUp = wifiUp;
    if (alert) {
      Serial.println("[led] alert — bright blink");
    } else if (!wifiUp) {
      Serial.println("[led] no Wi-Fi — off");
    } else {
      Serial.println("[led] clear — dim breathing");
    }
  }

  if (s_alert) {
    // Bright blink: full on for 250 ms, off for 250 ms.
    uint32_t phase = now % (BLINK_ON_MS + BLINK_OFF_MS);
    analogWrite(HP_STATUS_LED_PIN, ledDuty(phase < BLINK_ON_MS ? 255 : 0));
  } else if (!wifiUp) {
    analogWrite(HP_STATUS_LED_PIN, ledDuty(0));
  } else {
    // Dim breathing. sin() over a 2.6 s period, mapped to [BREATH_MIN, BREATH_MAX].
    float t = (float)(now % BREATH_PERIOD_MS) / BREATH_PERIOD_MS;
    float b = BREATH_MIN + (BREATH_MAX - BREATH_MIN) * (0.5f + 0.5f * sinf(2.0f * PI * t));
    analogWrite(HP_STATUS_LED_PIN, ledDuty((uint8_t)b));
  }
}

#endif  // HP_STATUS_LED_RGB

#else  // no HP_STATUS_LED_PIN — no-op build

void ledBegin() {}
void ledPump() {}
bool ledWifiUp() { return true; }

#endif
