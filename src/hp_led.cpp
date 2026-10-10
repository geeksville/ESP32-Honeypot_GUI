// Status LED implementation. See hp_led.h for the contract.
//
// Uses the Adafruit NeoPixel driver, which drives WS2812/WS2812B pixels over
// the ESP32's RMT peripheral — no bit-banging, no interrupts to babysit.
#include "hp_led.h"
#include "hp_events.h"

#if defined(HP_STATUS_LED_PIN)

#include <Adafruit_NeoPixel.h>

// One pixel, GRB order (the WS2812 default), NEO_KHZ800 signalling.
static Adafruit_NeoPixel s_px(1, HP_STATUS_LED_PIN, NEO_GRB + NEO_KHZ800);

// Breathing: brightness follows a sine wave between these bounds.
static const uint8_t  BREATH_MIN = 5;
static const uint8_t  BREATH_MAX = 40;
static const uint32_t BREATH_PERIOD_MS = 2600;   // one full in-out cycle

// Blink: full red for this long, then off, repeating.
static const uint32_t BLINK_ON_MS  = 250;
static const uint32_t BLINK_OFF_MS = 250;

static uint32_t s_lastMs = 0;
static bool     s_alert  = false;

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
  if (alert != s_alert) {
    s_alert = alert;
    Serial.printf("[led] %s\n", alert ? "alert — blinking red" : "clear — breathing green");
  }

  if (s_alert) {
    // 1 Hz blink: 250 ms on, 250 ms off.
    uint32_t phase = now % (BLINK_ON_MS + BLINK_OFF_MS);
    if (phase < BLINK_ON_MS) s_px.setPixelColor(0, s_px.Color(255, 0, 0));
    else                     s_px.clear();
  } else {
    // Breathing green. sin() over a 2.6 s period, mapped to [BREATH_MIN, BREATH_MAX].
    float t = (float)(now % BREATH_PERIOD_MS) / BREATH_PERIOD_MS;
    float b = BREATH_MIN + (BREATH_MAX - BREATH_MIN) * (0.5f + 0.5f * sinf(2.0f * PI * t));
    s_px.setPixelColor(0, s_px.Color(0, (uint8_t)b, 0));
  }

  s_px.show();
}

#else  // no HP_STATUS_LED_PIN — no-op build

void ledBegin() {}
void ledPump() {}

#endif
