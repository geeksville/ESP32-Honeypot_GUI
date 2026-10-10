#include "hp_config.h"
#include <LittleFS.h>

AppConfig g_cfg;

static const char* CFG_PATH = "/config.json";

// Ports we bait by default, chosen as the eight most-attacked services that fit
// the socket budget (see hp_common.h). 80 is deliberately absent: the admin UI
// lives there, and handing an attacker the real control panel would be a bad
// joke. Telnet earns its place several times over — it is the overwhelming
// majority of real traffic.
static const uint16_t DEFAULT_PORTS[] = {21, 22, 23, 25, 445, 3306, 3389, 8080};
static_assert(sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]) <= HP_MAX_PORTS,
              "default port list must fit AppConfig::ports");

void cfgSetDefaults(AppConfig& c) {
  memset(&c, 0, sizeof(c));
  c.portCount = sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]);
  memcpy(c.ports, DEFAULT_PORTS, sizeof(DEFAULT_PORTS));
  c.notifyMode         = NOTIFY_OFF;
  c.notifyMinSeverity  = SEV_NOTICE;
  c.notifyCooldownS    = 10;
  c.logToFlash         = true;
  c.alwaysAp           = false;
  c.mdnsAdvertise      = true;   // discoverability is the point; opt out if you must hide
  c.collectArtifacts   = false;
  c.panelAccess        = PANEL_PRIVATE;
  c.lanOnly            = false;
  c.artMaxBytes        = 262144;   // 256 KB covers essentially every IoT dropper
  hpCopy(c.hostname,  HP_STR, "srv-fileshare");
  hpCopy(c.shellUser, HP_STR, "admin");
  hpCopy(c.tz,        HP_STR, "UTC0");
}

// --------------------------------------------------------------- helpers ---

// Hostnames and usernames end up inside shell output we hand to an attacker.
// Restricting the alphabet keeps them from smuggling terminal escapes in.
static bool sanitiseIdent(char* s) {
  for (char* p = s; *p; ++p) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.') return false;
  }
  return true;
}

static bool looksLikeUrl(const char* u) {
  return strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0;
}

// ------------------------------------------------------------ load / save ---

bool cfgLoad() {
  cfgSetDefaults(g_cfg);

  File f = LittleFS.open(CFG_PATH, "r");
  if (!f || f.size() == 0) { if (f) f.close(); return false; }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, f);
  f.close();
  if (err) {
    Serial.printf("[cfg] %s is corrupt (%s) — using defaults\n", CFG_PATH, err.c_str());
    return false;
  }

  String reason;
  cfgApplyJson(doc.as<JsonObjectConst>(), reason, /*lenient=*/true);
  return strlen(g_cfg.ssid) > 0;
}

bool cfgSave() {
  JsonDocument doc;
  JsonObject o = doc.to<JsonObject>();
  cfgToJson(o, /*includeSecrets=*/true);

  // Write to a temp file and rename, so a power cut mid-write can't leave a
  // half-parsed config behind.
  File f = LittleFS.open("/config.tmp", "w");
  if (!f) return false;
  bool ok = serializeJson(doc, f) > 0;
  f.close();
  if (!ok) { LittleFS.remove("/config.tmp"); return false; }

  LittleFS.remove(CFG_PATH);
  return LittleFS.rename("/config.tmp", CFG_PATH);
}

void cfgReset() {
  cfgSetDefaults(g_cfg);
  LittleFS.remove(CFG_PATH);
}

bool cfgPortArmed(uint16_t port) {
  for (uint8_t i = 0; i < g_cfg.portCount; i++) if (g_cfg.ports[i] == port) return true;
  return false;
}

// ----------------------------------------------------------------- apply ---

// Assigns a string field only if the key is present and not the "unchanged"
// sentinel, so the UI never has to know the current secret to save the form.
static bool takeStr(JsonObjectConst in, const char* key, char* dst, size_t cap,
                    String& err, bool secret = false) {
  if (!in[key].is<const char*>()) return true;
  const char* v = in[key];
  if (secret && strcmp(v, CFG_SECRET_KEEP) == 0) return true;
  if (!hpCopy(dst, cap, v)) {
    err = String(key) + " is too long (max " + String(cap - 1) + " characters)";
    return false;
  }
  return true;
}

bool cfgApplyJson(JsonObjectConst in, String& err, bool lenient) {
  AppConfig n = g_cfg;   // stage into a copy; commit only if everything passes

  if (!takeStr(in, "ssid",       n.ssid,        HP_STR, err))       return false;
  if (!takeStr(in, "wifiPass",   n.wifiPass,    HP_STR, err, true)) return false;
  if (!takeStr(in, "adminPass",  n.adminPass,   HP_STR, err, true)) return false;
  if (!takeStr(in, "notifyUrl",  n.notifyUrl,   HP_URL, err))       return false;
  if (!takeStr(in, "notifyExtra", n.notifyExtra, HP_STR, err))      return false;
  if (!takeStr(in, "hostname",   n.hostname,    HP_STR, err))       return false;
  if (!takeStr(in, "shellUser",  n.shellUser,   HP_STR, err))       return false;
  if (!takeStr(in, "tz",         n.tz,          HP_STR, err))       return false;

  if (!sanitiseIdent(n.hostname) || n.hostname[0] == '\0') {
    err = "Hostname can only contain letters, numbers, dots, dashes and underscores";
    return false;
  }
  if (!sanitiseIdent(n.shellUser) || n.shellUser[0] == '\0') {
    err = "Shell user can only contain letters, numbers, dots, dashes and underscores";
    return false;
  }

  if (in["ports"].is<JsonArrayConst>()) {
    uint16_t tmp[HP_MAX_PORTS];
    uint8_t  count = 0;
    for (JsonVariantConst v : in["ports"].as<JsonArrayConst>()) {
      uint32_t p = v.as<uint32_t>();
      if (p == 80) { err = "Port 80 is reserved for this control panel"; return false; }
      if (p < 1 || p > 65535) { err = "Port " + String(p) + " is out of range"; return false; }
      bool dup = false;
      for (uint8_t i = 0; i < count; i++) if (tmp[i] == p) dup = true;
      if (dup) continue;
      if (count >= HP_MAX_PORTS) {
        // Loading a config saved by a build with a larger ceiling should keep
        // the Wi-Fi settings rather than throw the whole file away, so the
        // stored path truncates where the API path reports the problem.
        if (lenient) break;
        err = "You can arm at most " + String(HP_MAX_PORTS) +
              " ports at once — the network stack runs out of sockets beyond that";
        return false;
      }
      tmp[count++] = (uint16_t)p;
    }
    memset(n.ports, 0, sizeof(n.ports));
    memcpy(n.ports, tmp, count * sizeof(uint16_t));
    n.portCount = count;
  }

  if (in["notifyMode"].is<uint8_t>()) {
    uint8_t m = in["notifyMode"];
    if (m > NOTIFY_SYSLOG) { err = "Unknown alert destination"; return false; }
    n.notifyMode = m;
  }
  if (in["notifyMinSeverity"].is<uint8_t>()) {
    uint8_t s = in["notifyMinSeverity"];
    n.notifyMinSeverity = (s > SEV_ALERT) ? (uint8_t)SEV_ALERT : s;
  }
  if (in["notifyCooldownS"].is<uint16_t>()) {
    uint32_t c = in["notifyCooldownS"];
    n.notifyCooldownS = c > 3600 ? 3600 : c;
  }
  if (in["alwaysAp"].is<bool>())   n.alwaysAp   = in["alwaysAp"];
  if (in["logToFlash"].is<bool>()) n.logToFlash = in["logToFlash"];
  if (in["mdnsAdvertise"].is<bool>()) n.mdnsAdvertise = in["mdnsAdvertise"];
  if (in["collectArtifacts"].is<bool>()) n.collectArtifacts = in["collectArtifacts"];
  if (in["lanOnly"].is<bool>())         n.lanOnly          = in["lanOnly"];
  if (in["panelAccess"].is<uint8_t>()) {
    uint8_t v = in["panelAccess"];
    if (v > PANEL_ANYWHERE) { err = "Unknown control panel access mode"; return false; }
    // Opening the panel to the whole internet without a password would publish
    // the device to the first scanner that finds it.
    if (v == PANEL_ANYWHERE && n.adminPass[0] == '\0') {
      err = "Set a panel password before allowing access from anywhere";
      return false;
    }
    n.panelAccess = v;
  }
  if (in["artMaxBytes"].is<uint32_t>()) {
    uint32_t v = in["artMaxBytes"];
    if (v < 1024)      v = 1024;
    if (v > 1048576)   v = 1048576;
    n.artMaxBytes = v;
  }

  // A webhook that isn't a URL will just fail silently at 3am. Catch it here.
  if (n.notifyMode == NOTIFY_DISCORD || n.notifyMode == NOTIFY_TELEGRAM ||
      n.notifyMode == NOTIFY_GENERIC) {
    if (!looksLikeUrl(n.notifyUrl)) {
      err = "Alert URL must start with http:// or https://";
      return false;
    }
  }
  if (n.notifyMode == NOTIFY_TELEGRAM && n.notifyExtra[0] == '\0') {
    err = "Telegram needs a chat ID";
    return false;
  }
  if (n.notifyMode == NOTIFY_SYSLOG && n.notifyUrl[0] == '\0') {
    err = "Syslog needs a collector address";
    return false;
  }

  g_cfg = n;
  return true;
}

void cfgToJson(JsonObject out, bool includeSecrets) {
  out["ssid"] = g_cfg.ssid;
  if (includeSecrets) {
    out["wifiPass"]  = g_cfg.wifiPass;
    out["adminPass"] = g_cfg.adminPass;
  } else {
    // Report only whether a secret exists. Never its value.
    out["wifiPassSet"]  = strlen(g_cfg.wifiPass)  > 0;
    out["adminPassSet"] = strlen(g_cfg.adminPass) > 0;
  }

  JsonArray ports = out["ports"].to<JsonArray>();
  for (uint8_t i = 0; i < g_cfg.portCount; i++) ports.add(g_cfg.ports[i]);

  out["notifyMode"]        = g_cfg.notifyMode;
  out["notifyUrl"]         = g_cfg.notifyUrl;
  out["notifyExtra"]       = g_cfg.notifyExtra;
  out["notifyMinSeverity"] = g_cfg.notifyMinSeverity;
  out["notifyCooldownS"]   = g_cfg.notifyCooldownS;
  out["hostname"]          = g_cfg.hostname;
  out["shellUser"]         = g_cfg.shellUser;
  out["tz"]                = g_cfg.tz;
  out["alwaysAp"]          = g_cfg.alwaysAp;
  out["logToFlash"]        = g_cfg.logToFlash;
  out["mdnsAdvertise"]     = g_cfg.mdnsAdvertise;
  out["collectArtifacts"]  = g_cfg.collectArtifacts;
  out["panelAccess"]       = g_cfg.panelAccess;
  out["lanOnly"]           = g_cfg.lanOnly;
  out["artMaxBytes"]       = g_cfg.artMaxBytes;
}
