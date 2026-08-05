#include "hp_notify.h"
#include "hp_config.h"
#include "hp_events.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

static QueueHandle_t s_q = nullptr;
static uint32_t s_sent = 0, s_failed = 0, s_dropped = 0;
static uint32_t s_lastSendMs = 0;

// --------------------------------------------------------------- payloads ---

// Escapes a string for embedding in a JSON string literal we build by hand.
static String jsonEscape(const char* s) {
  String o;
  o.reserve(strlen(s) + 8);
  for (const char* p = s; *p; ++p) {
    switch (*p) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': o += "\\r";  break;
      case '\t': o += "\\t";  break;
      default:
        if ((unsigned char)*p < 0x20) o += '.';
        else o += *p;
    }
  }
  return o;
}

static const char* SEV_ICON[3] = {"\xE2\x97\x8B", "\xE2\x97\x91", "\xE2\x97\x8F"};  // ○ ◑ ●

static String humanLine(const Event& e) {
  char ip[16];
  hpFormatIp(e.ip, ip, sizeof(ip));
  String s;
  s += SEV_ICON[e.severity < 3 ? e.severity : 0];
  s += " ";
  s += g_cfg.hostname;
  s += " — ";
  s += evKindName(e.kind);
  s += "\n";
  s += ip;
  if (e.port) { s += " → port "; s += String(e.port); }
  s += "\n";
  s += e.detail;
  return s;
}

static String buildBody(const Event& e) {
  switch (g_cfg.notifyMode) {
    case NOTIFY_DISCORD:
      return String("{\"content\":\"") + jsonEscape(humanLine(e).c_str()) + "\"}";

    case NOTIFY_TELEGRAM:
      return String("{\"chat_id\":\"") + jsonEscape(g_cfg.notifyExtra) +
             "\",\"text\":\"" + jsonEscape(humanLine(e).c_str()) + "\"}";

    case NOTIFY_GENERIC: {
      // Structured, for a SIEM. Field names match the NDJSON on flash.
      char ip[16];
      hpFormatIp(e.ip, ip, sizeof(ip));
      JsonDocument d;
      d["source"]   = g_cfg.hostname;
      d["seq"]      = e.seq;
      d["ts"]       = e.ts;
      d["ip"]       = ip;
      d["port"]     = e.port;
      d["kind"]     = evKindName(e.kind);
      d["severity"] = evSevName(e.severity);
      d["detail"]   = e.detail;
      String out;
      serializeJson(d, out);
      return out;
    }
    default:
      return String();
  }
}

// ---------------------------------------------------------------- syslog ---

static WiFiUDP s_udp;

static bool sendSyslog(const Event& e) {
  IPAddress host;
  if (!host.fromString(g_cfg.notifyUrl) && !WiFi.hostByName(g_cfg.notifyUrl, host)) return false;
  uint16_t port = g_cfg.notifyExtra[0] ? (uint16_t)atoi(g_cfg.notifyExtra) : 514;

  // RFC 5424. Facility 13 (log audit) × 8 + severity → warning/notice/info.
  uint8_t sysSev = e.severity == SEV_ALERT ? 4 : (e.severity == SEV_NOTICE ? 5 : 6);
  char ip[16];
  hpFormatIp(e.ip, ip, sizeof(ip));

  char tsBuf[32] = "-";
  if (e.ts) {
    time_t t = e.ts;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(tsBuf, sizeof(tsBuf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
  }

  String msg;
  msg.reserve(320);
  msg += "<" + String(13 * 8 + sysSev) + ">1 " + tsBuf + " " + g_cfg.hostname +
         " honeypot - " + evKindName(e.kind) +
         " [hp@47111 src=\"" + ip + "\" port=\"" + String(e.port) +
         "\" sev=\"" + evSevName(e.severity) + "\"] " + e.detail;

  if (!s_udp.beginPacket(host, port)) return false;
  s_udp.write((const uint8_t*)msg.c_str(), msg.length());
  return s_udp.endPacket() == 1;
}

// -------------------------------------------------------------- delivery ---

static bool deliver(const Event& e, String& err) {
  if (g_cfg.notifyMode == NOTIFY_OFF) { err = "Alerts are turned off"; return false; }
  if (WiFi.status() != WL_CONNECTED)  { err = "Not connected to Wi-Fi";  return false; }

  if (g_cfg.notifyMode == NOTIFY_SYSLOG) {
    if (sendSyslog(e)) return true;
    err = "Could not reach the syslog collector";
    return false;
  }

  String body = buildBody(e);
  if (!body.length()) { err = "Nothing to send"; return false; }

  HTTPClient http;
  http.setTimeout(6000);
  http.setConnectTimeout(4000);
  if (!http.begin(g_cfg.notifyUrl)) { err = "That URL could not be parsed"; return false; }
  http.addHeader("Content-Type", "application/json");
  http.addHeader("User-Agent", "esp32-honeypot/" HP_VERSION);
  int code = http.POST(body);
  String reply = code > 0 ? http.getString().substring(0, 120) : String();
  http.end();

  if (code >= 200 && code < 300) return true;
  err = code > 0 ? ("The destination replied " + String(code) +
                    (reply.length() ? (": " + reply) : ""))
                 : ("Connection failed (" + String(code) + ")");
  return false;
}

// ------------------------------------------------------------------ task ---

static void notifyTask(void*) {
  Event e;
  for (;;) {
    if (xQueueReceive(s_q, &e, portMAX_DELAY) != pdTRUE) continue;
    if (g_cfg.notifyMode == NOTIFY_OFF) continue;
    if (e.severity < g_cfg.notifyMinSeverity) continue;

    // A scan hits a dozen ports in a second. Without a floor between sends the
    // device spends all its time talking to Discord instead of listening.
    uint32_t gap = (uint32_t)g_cfg.notifyCooldownS * 1000UL;
    uint32_t since = millis() - s_lastSendMs;
    if (s_lastSendMs && since < gap) vTaskDelay(pdMS_TO_TICKS(gap - since));

    String err;
    if (deliver(e, err)) {
      s_sent++;
    } else {
      s_failed++;
      Serial.printf("[notify] delivery failed: %s\n", err.c_str());
    }
    s_lastSendMs = millis();
  }
}

void notifyBegin() {
  s_q = xQueueCreate(24, sizeof(Event));
  xTaskCreatePinnedToCore(notifyTask, "hp_notify", 6144, nullptr, 1, nullptr, 0);
}

void notifyQueue(const Event& e) {
  if (!s_q || g_cfg.notifyMode == NOTIFY_OFF) return;
  if (e.severity < g_cfg.notifyMinSeverity) return;
  if (xQueueSend(s_q, &e, 0) != pdTRUE) s_dropped++;
}

bool notifyTest(String& err) {
  Event e{};
  e.seq      = 0;
  e.ts       = (uint32_t)time(nullptr);
  e.uptimeMs = millis();
  e.ip       = 0;
  e.port     = 0;
  e.kind     = EV_SYSTEM;
  e.severity = SEV_NOTICE;
  hpCopy(e.detail, HP_DETAIL_LEN, "Test alert from your honeypot. Delivery is working.");
  return deliver(e, err);
}

uint32_t notifySentCount()    { return s_sent; }
uint32_t notifyFailCount()    { return s_failed; }
uint32_t notifyDroppedCount() { return s_dropped; }
