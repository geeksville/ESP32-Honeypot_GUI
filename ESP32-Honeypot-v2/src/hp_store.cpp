#include "hp_store.h"
#include "hp_config.h"
#include <LittleFS.h>
#include <SPIFFS.h>
#include <WebServer.h>

// Rotate at 512 KB. With one retained generation that caps the log at ~1 MB,
// which fits every board this firmware targets, including 4 MB ones.
static const size_t LOG_ROTATE_BYTES = 512UL * 1024UL;

static size_t s_logSize = 0;
static bool   s_mounted = false;

// ------------------------------------------------------------- migration ---

// v1 stored its config on a SPIFFS-formatted partition. Read it before we
// reformat, so upgrading doesn't silently lose someone's Wi-Fi credentials.
static bool migrateFromSpiffs() {
  if (!SPIFFS.begin(false)) return false;

  bool carried = false;
  File f = SPIFFS.open("/config.json", "r");
  if (f && f.size() > 0) {
    JsonDocument doc;
    if (deserializeJson(doc, f) == DeserializationError::Ok) {
      cfgSetDefaults(g_cfg);
      hpCopy(g_cfg.ssid,      HP_STR, doc["ssid"]      | "");
      hpCopy(g_cfg.wifiPass,  HP_STR, doc["password"]  | "");
      hpCopy(g_cfg.notifyUrl, HP_URL, doc["webhook"]   | "");
      if (strlen(g_cfg.notifyUrl)) g_cfg.notifyMode = NOTIFY_DISCORD;

      uint8_t n = 0;
      for (JsonVariantConst v : doc["ports"].as<JsonArrayConst>()) {
        uint32_t p = v.as<uint32_t>();
        if (p == 80 || p < 1 || p > 65535 || n >= HP_MAX_PORTS) continue;
        g_cfg.ports[n++] = (uint16_t)p;
      }
      if (n) g_cfg.portCount = n;
      carried = true;
      Serial.println("[store] carried v1 config over from SPIFFS");
    }
  }
  if (f) f.close();
  SPIFFS.end();
  return carried;
}

bool storeBegin() {
  if (LittleFS.begin(false)) {
    s_mounted = true;
  } else {
    // Either blank flash or a v1 SPIFFS image. Try to rescue the config first.
    bool carried = migrateFromSpiffs();
    Serial.println("[store] formatting flash as LittleFS");
    if (!LittleFS.begin(true)) {
      Serial.println("[store] flash unusable — running without persistence");
      return false;
    }
    s_mounted = true;
    if (carried) cfgSave();
  }

  File f = LittleFS.open(LOG_PATH, "r");
  s_logSize = f ? f.size() : 0;
  if (f) f.close();
  return true;
}

// ------------------------------------------------------------------- log ---

static void rotateIfNeeded() {
  if (s_logSize < LOG_ROTATE_BYTES) return;
  LittleFS.remove(LOG_PREV);
  LittleFS.rename(LOG_PATH, LOG_PREV);
  s_logSize = 0;
  Serial.println("[store] rotated event log");
}

// One JSON object per line: greppable with jq, ingestible by Filebeat/Vector
// without a parser, and appendable without rewriting the file.
static void writeNdjson(File& f, const Event& e) {
  char ip[16];
  hpFormatIp(e.ip, ip, sizeof(ip));
  f.printf("{\"seq\":%lu,\"ts\":%lu,\"up\":%lu,\"ip\":\"%s\",\"port\":%u,"
           "\"kind\":%u,\"sev\":%u,\"detail\":\"",
           (unsigned long)e.seq, (unsigned long)e.ts, (unsigned long)e.uptimeMs,
           ip, e.port, e.kind, e.severity);
  // detail is already sanitised on the way in, but escape the JSON metachars.
  for (const char* p = e.detail; *p; ++p) {
    if (*p == '"' || *p == '\\') { f.write('\\'); f.write(*p); }
    else f.write(*p);
  }
  f.println("\"}");
}

void storeAppendEvent(const Event& e) {
  if (!s_mounted || !g_cfg.logToFlash) return;
  rotateIfNeeded();
  File f = LittleFS.open(LOG_PATH, "a");
  if (!f) return;
  size_t before = f.size();
  writeNdjson(f, e);
  s_logSize = f.size() ? f.size() : before;
  f.close();
}

size_t storeLogSize()  { return s_logSize; }
size_t storeFsUsed()   { return s_mounted ? LittleFS.usedBytes()  : 0; }
size_t storeFsTotal()  { return s_mounted ? LittleFS.totalBytes() : 0; }

void storeClearLog() {
  LittleFS.remove(LOG_PATH);
  LittleFS.remove(LOG_PREV);
  s_logSize = 0;
}

// ---------------------------------------------------------------- export ---

static const char* KIND_NAMES[EV_KIND_COUNT] = {
  "connect", "probe", "login", "command", "download", "disconnect", "system"
};
static const char* SEV_NAMES[3] = {"info", "notice", "alert"};

// Rewrites one NDJSON line as CSV. Cheap enough to do per line while streaming.
static String ndjsonLineToCsv(const String& line) {
  JsonDocument d;
  if (deserializeJson(d, line) != DeserializationError::Ok) return String();
  uint8_t k = d["kind"] | 0, s = d["sev"] | 0;
  String detail = d["detail"] | "";
  detail.replace("\"", "\"\"");
  String out;
  out.reserve(line.length() + 32);
  out += String((unsigned long)(d["ts"] | 0)) + ",";
  out += String((unsigned long)(d["up"] | 0)) + ",";
  out += String((const char*)(d["ip"] | "")) + ",";
  out += String((unsigned)(d["port"] | 0)) + ",";
  out += String(k < EV_KIND_COUNT ? KIND_NAMES[k] : "?") + ",";
  out += String(s < 3 ? SEV_NAMES[s] : "?") + ",";
  out += "\"" + detail + "\"\n";
  return out;
}

void storeStreamLog(WebServer& srv, bool asCsv) {
  srv.setContentLength(CONTENT_LENGTH_UNKNOWN);
  srv.send(200, asCsv ? "text/csv" : "application/x-ndjson", "");
  if (asCsv) srv.sendContent("timestamp,uptime_ms,ip,port,kind,severity,detail\n");

  // Oldest generation first so the export reads chronologically.
  const char* files[2] = {LOG_PREV, LOG_PATH};
  for (uint8_t i = 0; i < 2; i++) {
    File f = LittleFS.open(files[i], "r");
    if (!f) continue;
    if (!asCsv) {
      // Straight passthrough in 1 KB chunks — no parsing, no RAM spike.
      uint8_t buf[1024];
      while (f.available()) {
        size_t n = f.read(buf, sizeof(buf));
        srv.sendContent((const char*)buf, n);
      }
    } else {
      while (f.available()) {
        String line = f.readStringUntil('\n');
        if (line.length() < 2) continue;
        String row = ndjsonLineToCsv(line);
        if (row.length()) srv.sendContent(row);
      }
    }
    f.close();
  }
  srv.sendContent("");
}
