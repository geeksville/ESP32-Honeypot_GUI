// ESP32 Honeypot v2
//
// Work is split across cores so a slow webhook or a browser polling the
// dashboard can never delay the thing that actually matters — accepting and
// answering connections on the baited ports.
//
//   core 1 : honeypot listeners (hp_services)
//   core 0 : control panel, Wi-Fi supervision, alert delivery
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include "hp_common.h"
#include "hp_config.h"
#include "hp_store.h"
#include "hp_events.h"
#include "hp_notify.h"
#include "hp_services.h"
#include "hp_artifacts.h"
#include "hp_web.h"

static const char* AP_SSID = "honeypot-setup";
static const char* AP_PASS = "trapdoor123";     // ≥8 chars, WPA2 minimum

static bool s_apUp = false;

// ------------------------------------------------------------------ wifi ---

static void startAp(const char* why) {
  if (s_apUp) return;
  WiFi.mode(g_cfg.ssid[0] ? WIFI_AP_STA : WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  s_apUp = true;
  webSetApFallback(true);
  Serial.printf("\n[wifi] %s — setup network is up\n", why);
  Serial.printf("[wifi]   network : %s\n", AP_SSID);
  Serial.printf("[wifi]   password: %s\n", AP_PASS);
  Serial.printf("[wifi]   panel   : http://%s/\n", WiFi.softAPIP().toString().c_str());
}

static void stopApIfIdle() {
  if (!s_apUp || g_cfg.alwaysAp) return;
  // Restricting the panel to the setup network only makes sense while that
  // network exists. Closing it here would leave the setting unreachable and the
  // device recoverable only by reflashing.
  if (g_cfg.panelAccess == PANEL_AP_ONLY) return;
  if (WiFi.softAPgetStationNum() > 0) return;   // don't cut someone off mid-setup
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  s_apUp = false;
  webSetApFallback(false);
  Serial.println("[wifi] setup network closed, station mode only");
}

static bool connectSta(uint32_t timeoutMs) {
  if (!g_cfg.ssid[0]) return false;
  WiFi.mode(s_apUp ? WIFI_AP_STA : WIFI_STA);
  WiFi.setSleep(false);                     // latency matters more than mA here
  WiFi.setAutoReconnect(true);
  WiFi.begin(g_cfg.ssid, g_cfg.wifiPass);

  Serial.printf("[wifi] joining %s", g_cfg.ssid);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < timeoutMs) {
    delay(250);
    Serial.print('.');
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) return false;
  Serial.printf("[wifi] joined, address %s (%d dBm)\n",
                WiFi.localIP().toString().c_str(), WiFi.RSSI());
  return true;
}

static void syncClock() {
  // Real timestamps are what make the capture correlatable with anything else.
  configTzTime(g_cfg.tz, "pool.ntp.org", "time.nist.gov");
  uint32_t t0 = millis();
  while (time(nullptr) < 1700000000 && millis() - t0 < 8000) delay(200);
  if (time(nullptr) > 1700000000) {
    time_t now = time(nullptr);
    Serial.printf("[time] synced: %s", ctime(&now));
  } else {
    Serial.println("[time] NTP did not answer; events will carry uptime only");
  }
}

// ----------------------------------------------------------------- tasks ---

// The honeypot. Tight loop, nothing in it may block.
static void potTask(void*) {
  svcApplyConfig();
  for (;;) {
    svcPump();
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}

// Control panel plus Wi-Fi supervision.
static void netTask(void*) {
  uint32_t nextCheck = 0;
  uint32_t backoffMs = 10000;
  uint8_t  lowHeap   = 0;

  for (;;) {
    webPump();

    if (g_cfg.ssid[0] && (int32_t)(millis() - nextCheck) >= 0) {
      // Station and SoftAP share one radio: every scan/connect attempt drops
      // the AP beacon for seconds. If somebody is connected to the setup
      // network they are almost certainly there to fix the Wi-Fi settings, so
      // hold off and keep their connection stable.
      if (s_apUp && WiFi.softAPgetStationNum() > 0) {
        nextCheck = millis() + 15000;
        vTaskDelay(pdMS_TO_TICKS(5));
        continue;
      }
      if (WiFi.status() != WL_CONNECTED) {
        startAp("station link down");
        if (connectSta(8000)) {
          backoffMs = 10000;
          syncClock();
          evLog(EV_SYSTEM, SEV_INFO, 0, 0, "rejoined %s as %s",
                g_cfg.ssid, WiFi.localIP().toString().c_str());
        } else {
          // The configured network is often just out of range — the device
          // moved, or the router is down. Keep retrying with backoff and leave
          // the setup AP up. Rebooting here (as this used to) takes the control
          // panel down every couple of minutes, which is precisely when the
          // operator needs it to correct the Wi-Fi setting.
          backoffMs = backoffMs < 60000 ? backoffMs * 2 : 60000;
          Serial.printf("[wifi] %s not reachable, next try in %lus\n",
                        g_cfg.ssid, (unsigned long)(backoffMs / 1000));
        }
      } else {
        backoffMs = 10000;
        if (g_cfg.panelAccess == PANEL_AP_ONLY) startAp("panel is restricted to the setup network");
        else                                    stopApIfIdle();
      }

      // Unattended survivability. Weeks of attacker-controlled input through
      // String-heavy parsing will fragment the heap eventually; a device that
      // is still powered but too short on memory to accept a connection is
      // worse than one that restarts and carries on. Flash keeps the log.
      if (ESP.getFreeHeap() < 24576) {
        if (++lowHeap >= 3) {
          Serial.printf("[health] free heap %u for three checks — restarting\n",
                        ESP.getFreeHeap());
          evLog(EV_SYSTEM, SEV_ALERT, 0, 0, "restarting: heap exhausted (%u bytes free)",
                ESP.getFreeHeap());
          delay(250);
          ESP.restart();
        }
      } else {
        lowHeap = 0;
      }

      nextCheck = millis() + backoffMs;
    }
    vTaskDelay(pdMS_TO_TICKS(5));
  }
}

// ----------------------------------------------------------------- setup ---

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.printf("\n\n=== ESP32 Honeypot %s ===\n", HP_VERSION);
  Serial.printf("[boot] %s, %u KB heap, %u KB PSRAM\n",
                ESP.getChipModel(), ESP.getFreeHeap() / 1024, ESP.getPsramSize() / 1024);

  cfgSetDefaults(g_cfg);
  storeBegin();
  bool configured = cfgLoad();
  evBegin();
  notifyBegin();
  artBegin();

  if (!configured) {
    Serial.println("[boot] no Wi-Fi configured yet");
    startAp("first run");
  } else if (!connectSta(15000)) {
    startAp("could not join the configured network");
  } else {
    syncClock();
    if (g_cfg.panelAccess == PANEL_AP_ONLY) startAp("panel is restricted to the setup network");
  }

  if (!g_cfg.adminPass[0]) {
    Serial.println("[warn] the control panel has no password — anyone on this "
                   "network can change the trap. Set one in Settings.");
  }

  webBegin();
  evLog(EV_SYSTEM, SEV_INFO, 0, 0, "honeypot started, %u ports armed", g_cfg.portCount);

  xTaskCreatePinnedToCore(potTask, "hp_pot", 12288, nullptr, 3, nullptr, 1);
  xTaskCreatePinnedToCore(netTask, "hp_net", 8192, nullptr, 2, nullptr, 0);
}

void loop() {
  // Everything runs in tasks. Yield the Arduino loop task entirely.
  vTaskDelay(pdMS_TO_TICKS(1000));
}
