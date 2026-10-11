#include "hp_web.h"
#include "hp_config.h"
#include "hp_events.h"
#include "hp_services.h"
#include "hp_store.h"
#include "hp_notify.h"
#include "hp_artifacts.h"
#include "ui_index.h"
#include <WiFi.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <esp_system.h>

static WebServer s_srv(80);
static bool      s_apFallback = false;

// Defined below webBegin; also called from handlePostConfig so the advertised
// records track the armed set and the toggle without a reboot.
static void mdnsApply();

void webSetApFallback(bool active) { s_apFallback = active; }

// -------------------------------------------------------- source gating ---

// The bait ports are meant to be forwarded to the internet. This one is not.
// Rather than relying on the operator's firewall being right, every request is
// checked against where it came from, so a mistaken port-80 forward exposes
// nothing.

// True when the client is on the device's own SoftAP subnet.
static bool isApClient(const IPAddress& ip) {
  IPAddress ap = WiFi.softAPIP();
  return ap[0] != 0 && ip[0] == ap[0] && ip[1] == ap[1] && ip[2] == ap[2];
}

static uint32_t s_blocked = 0;

static bool sourceAllowed() {
  IPAddress ip = s_srv.client().remoteIP();

  // An unprotected panel is never reachable from a public address, whatever the
  // firewall does. It stays reachable on the local network though: locking that
  // down too would strand anyone who set up Wi-Fi before setting a password,
  // with no way back in except rejoining the setup AP — and the threat that
  // actually matters here is exposure to the internet, which this already stops.
  uint8_t mode = g_cfg.panelAccess;
  if (g_cfg.adminPass[0] == '\0' && mode > PANEL_PRIVATE) mode = PANEL_PRIVATE;

  switch (mode) {
    case PANEL_ANYWHERE: return true;
    case PANEL_PRIVATE:  return isApClient(ip) || hpIsPrivateV4((uint32_t)ip);
    default:             return isApClient(ip);
  }
}

// Answers a rejected request as a plain web server would. Advertising "honeypot
// control panel, access denied" to a scanner would defeat the point.
static void denySource() {
  IPAddress ip = s_srv.client().remoteIP();
  if ((s_blocked++ & 0x0F) == 0) {          // log the first, then every 16th
    evLog(EV_PROBE, SEV_ALERT, (uint32_t)ip, 80,
          "control panel refused for %s — outside the allowed source range",
          s_srv.uri().c_str());
  }
  s_srv.sendHeader("Server", "Apache/2.4.52 (Ubuntu)");
  s_srv.send(404, "text/html",
             "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n"
             "<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n"
             "<p>The requested URL was not found on this server.</p>\n<hr>\n"
             "<address>Apache/2.4.52 (Ubuntu) Server Port 80</address>\n</body></html>\n");
}

// Wraps a handler so no route can forget the check.
static bool gateSource() {
  if (sourceAllowed()) return true;
  denySource();
  return false;
}

// ------------------------------------------------------------------ auth ---

// One session at a time is plenty for a device like this, and it keeps the
// whole auth surface to a token compare.
static char     s_token[33] = {0};
static uint32_t s_tokenIssued = 0;
static const uint32_t TOKEN_TTL_MS = 60UL * 60UL * 1000UL;

// Failed logins back off, so the panel can't be brute-forced over the LAN.
static uint8_t  s_failures = 0;
static uint32_t s_lockedUntil = 0;

static bool authRequired() { return strlen(g_cfg.adminPass) > 0; }

static void mintToken() {
  static const char* AB = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  for (uint8_t i = 0; i < 32; i++) s_token[i] = AB[esp_random() % 62];
  s_token[32] = 0;
  s_tokenIssued = millis();
}

// Constant-time-ish compare so a timing oracle can't peel the token apart.
static bool tokenMatches(const String& given) {
  if (!s_token[0] || given.length() != 32) return false;
  if (millis() - s_tokenIssued > TOKEN_TTL_MS) { s_token[0] = 0; return false; }
  uint8_t diff = 0;
  for (uint8_t i = 0; i < 32; i++) diff |= (uint8_t)(s_token[i] ^ given[i]);
  return diff == 0;
}

static bool guard() {
  if (!gateSource()) return false;
  if (!authRequired()) return true;
  if (tokenMatches(s_srv.header("X-Auth"))) return true;
  s_srv.send(401, "application/json", "{\"error\":\"Sign in to continue\"}");
  return false;
}

static void sendJson(int code, JsonDocument& doc) {
  String out;
  serializeJson(doc, out);
  s_srv.sendHeader("Cache-Control", "no-store");
  s_srv.send(code, "application/json", out);
}

static void sendError(int code, const String& msg) {
  JsonDocument d;
  d["error"] = msg;
  sendJson(code, d);
}

static bool readBody(JsonDocument& doc) {
  if (!s_srv.hasArg("plain")) { sendError(400, "The request had no body"); return false; }
  if (deserializeJson(doc, s_srv.arg("plain")) != DeserializationError::Ok) {
    sendError(400, "The request body was not valid JSON");
    return false;
  }
  return true;
}

// ----------------------------------------------------------------- state ---

static const uint8_t MAX_EVENTS_PER_POLL = 40;

static void handleState() {
  if (!guard()) return;

  uint32_t cursor = s_srv.hasArg("cursor") ? strtoul(s_srv.arg("cursor").c_str(), nullptr, 10) : 0;
  // A fresh page asks for cursor=0; give it the tail of the ring, not the head.
  bool cold = !s_srv.hasArg("cursor");

  JsonDocument doc;
  JsonObject root = doc.to<JsonObject>();

  JsonObject dev = root["device"].to<JsonObject>();
  dev["version"]   = HP_VERSION;
  dev["hostname"]  = g_cfg.hostname;
  dev["mdnsUrl"]   = String("http://") + g_cfg.hostname + ".local/";
  dev["mdnsAdvertise"] = g_cfg.mdnsAdvertise;
  dev["uptimeS"]   = millis() / 1000;
  dev["heapFree"]  = ESP.getFreeHeap();
  dev["heapMin"]   = ESP.getMinFreeHeap();
  dev["psram"]     = ESP.getPsramSize();
  dev["chip"]      = ESP.getChipModel();
  dev["ringCap"]   = evRingCapacity();
  dev["fsUsed"]    = storeFsUsed();
  dev["fsTotal"]   = storeFsTotal();
  dev["logBytes"]  = storeLogSize();
  time_t now = time(nullptr);
  dev["clock"]     = (now > 1700000000) ? (uint32_t)now : 0;

  JsonObject net = root["net"].to<JsonObject>();
  bool sta = WiFi.status() == WL_CONNECTED;
  net["online"]  = sta;
  net["ssid"]    = sta ? WiFi.SSID() : String(g_cfg.ssid);
  net["ip"]      = sta ? WiFi.localIP().toString() : String();
  net["rssi"]    = sta ? WiFi.RSSI() : 0;
  net["mac"]     = WiFi.macAddress();
  net["ap"]      = s_apFallback;
  net["apIp"]    = s_apFallback ? WiFi.softAPIP().toString() : String();
  net["apClients"] = s_apFallback ? WiFi.softAPgetStationNum() : 0;

  JsonObject al = root["alerts"].to<JsonObject>();
  al["mode"]    = g_cfg.notifyMode;
  al["sent"]    = notifySentCount();
  al["failed"]  = notifyFailCount();
  al["dropped"] = notifyDroppedCount();

  // Only the summary here — the full sample list is fetched separately, and
  // only when the count changes, so a 2 s poll stays small.
  JsonObject art = root["artifacts"].to<JsonObject>();
  art["on"]     = g_cfg.collectArtifacts;
  art["count"]  = artCount();
  art["bytes"]  = artBytes();
  art["failed"] = artFailures();

  uint32_t knownCat = s_srv.hasArg("cat") ? strtoul(s_srv.arg("cat").c_str(), nullptr, 10) : 0;
  svcStatusJson(root["services"].to<JsonObject>(), knownCat);
  evStatsJson(root["stats"].to<JsonObject>());

  root["authRequired"] = authRequired();
  root["panelAccess"]  = g_cfg.panelAccess;
  root["panelBlocked"] = s_blocked;

  // Events newer than the cursor, oldest first.
  static Event buf[MAX_EVENTS_PER_POLL];
  uint32_t newCursor = cursor;
  size_t n = evSince(cold ? (evLatestSeq() > MAX_EVENTS_PER_POLL
                             ? evLatestSeq() - MAX_EVENTS_PER_POLL : 0)
                          : cursor,
                     buf, MAX_EVENTS_PER_POLL, &newCursor);

  JsonArray evs = root["events"].to<JsonArray>();
  for (size_t i = 0; i < n; i++) {
    JsonObject e = evs.add<JsonObject>();
    char ip[16];
    hpFormatIp(buf[i].ip, ip, sizeof(ip));
    e["seq"]    = buf[i].seq;
    e["ts"]     = buf[i].ts;
    e["agoMs"]  = millis() - buf[i].uptimeMs;
    e["ip"]     = ip;
    e["port"]   = buf[i].port;
    e["kind"]   = evKindName(buf[i].kind);
    e["sev"]    = buf[i].severity;
    e["detail"] = buf[i].detail;
  }
  root["cursor"] = newCursor;
  root["latest"] = evLatestSeq();

  sendJson(200, doc);
}

// ---------------------------------------------------------------- routes ---

static void handleRoot() {
  if (!gateSource()) return;
  s_srv.sendHeader("Content-Encoding", "gzip");
  s_srv.sendHeader("Cache-Control", "public, max-age=600");
  s_srv.send_P(200, "text/html", (const char*)UI_INDEX_GZ, UI_INDEX_GZ_LEN);
}

static void handleLogin() {
  if (!gateSource()) return;
  JsonDocument body;
  if (!readBody(body)) return;

  if (millis() < s_lockedUntil) {
    sendError(429, "Too many attempts. Try again in " +
                   String((s_lockedUntil - millis()) / 1000) + "s");
    return;
  }
  const char* given = body["password"] | "";
  if (!authRequired() || strcmp(given, g_cfg.adminPass) == 0) {
    s_failures = 0;
    mintToken();
    JsonDocument d;
    d["token"] = s_token;
    sendJson(200, d);
    return;
  }
  if (++s_failures >= 5) { s_lockedUntil = millis() + 60000; s_failures = 0; }
  sendError(401, "That password is not correct");
}

static void handleGetConfig() {
  if (!guard()) return;
  JsonDocument doc;
  JsonObject o = doc.to<JsonObject>();
  cfgToJson(o, /*includeSecrets=*/false);
  sendJson(200, doc);
}

static void handlePostConfig() {
  if (!guard()) return;
  JsonDocument body;
  if (!readBody(body)) return;

  String err;
  if (!cfgApplyJson(body.as<JsonObjectConst>(), err)) { sendError(400, err); return; }
  if (!cfgSave()) { sendError(500, "The settings could not be written to flash"); return; }

  // Re-arm immediately: changing the bait shouldn't need a reboot.
  svcApplyConfig();
  // The advertised mDNS records follow the armed set and the toggle. A hostname
  // change also lands here, and MDNS.begin() re-registers under the new name.
  mdnsApply();
  evLog(EV_SYSTEM, SEV_INFO, 0, 0, "settings changed from the control panel");

  JsonDocument d;
  d["ok"] = true;
  d["rebootNeeded"] = body["ssid"].is<const char*>() || body["wifiPass"].is<const char*>();
  sendJson(200, d);
}

static void handleScan() {
  if (!guard()) return;
  int n = WiFi.scanNetworks(false, false, false, 200);
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < n && i < 24; i++) {
    JsonObject o = arr.add<JsonObject>();
    o["ssid"] = WiFi.SSID(i);
    o["rssi"] = WiFi.RSSI(i);
    o["open"] = WiFi.encryptionType(i) == WIFI_AUTH_OPEN;
  }
  WiFi.scanDelete();
  sendJson(200, doc);
}

static void handleExport() {
  if (!guard()) return;
  bool csv = s_srv.arg("fmt") == "csv";
  s_srv.sendHeader("Content-Disposition",
                   String("attachment; filename=\"honeypot-events.") + (csv ? "csv" : "ndjson") + "\"");
  storeStreamLog(s_srv, csv);
}

void webBegin() {
  // Only headers we name are retained by WebServer, so ask for the auth one.
  const char* wanted[] = {"X-Auth"};
  s_srv.collectHeaders(wanted, 1);

  s_srv.on("/",              HTTP_GET,  handleRoot);
  s_srv.on("/api/state",     HTTP_GET,  handleState);
  s_srv.on("/api/config",    HTTP_GET,  handleGetConfig);
  s_srv.on("/api/config",    HTTP_POST, handlePostConfig);
  s_srv.on("/api/login",     HTTP_POST, handleLogin);
  s_srv.on("/api/scan",      HTTP_GET,  handleScan);
  s_srv.on("/api/export",    HTTP_GET,  handleExport);

  s_srv.on("/api/artifacts", HTTP_GET, []() {
    if (!guard()) return;
    JsonDocument doc;
    artListJson(doc.to<JsonArray>());
    sendJson(200, doc);
  });

  s_srv.on("/api/artifact", HTTP_GET, []() {
    if (!guard()) return;
    if (!artStreamBlob(s_srv, s_srv.arg("sha"))) sendError(404, "No such sample");
  });

  s_srv.on("/api/artifacts/clear", HTTP_POST, []() {
    if (!guard()) return;
    artClear();
    evLog(EV_SYSTEM, SEV_INFO, 0, 0, "collected samples deleted from the control panel");
    JsonDocument d; d["ok"] = true; sendJson(200, d);
  });

  s_srv.on("/api/test-alert", HTTP_POST, []() {
    if (!guard()) return;
    String err;
    JsonDocument d;
    if (notifyTest(err)) { d["ok"] = true; sendJson(200, d); }
    else                 { sendError(502, err); }
  });

  s_srv.on("/api/clear-log", HTTP_POST, []() {
    if (!guard()) return;
    storeClearLog();
    evClearStats();
    evLog(EV_SYSTEM, SEV_INFO, 0, 0, "capture log cleared from the control panel");
    JsonDocument d; d["ok"] = true; sendJson(200, d);
  });

  s_srv.on("/api/reboot", HTTP_POST, []() {
    if (!guard()) return;
    JsonDocument d; d["ok"] = true; sendJson(200, d);
    delay(200);
    ESP.restart();
  });

  s_srv.on("/api/reset", HTTP_POST, []() {
    if (!guard()) return;
    cfgReset();
    storeClearLog();
    JsonDocument d; d["ok"] = true; sendJson(200, d);
    delay(200);
    ESP.restart();
  });

  // Captive-portal style: anything unknown lands on the panel rather than a 404,
  // so phones that probe for connectivity open the setup page by themselves.
  s_srv.onNotFound([]() {
    if (!gateSource()) return;
    if (s_srv.uri().startsWith("/api/")) { sendError(404, "No such endpoint"); return; }
    s_srv.sendHeader("Location", "/", true);
    s_srv.send(302, "text/plain", "");
  });

  s_srv.begin();

  mdnsApply();
}

// ---------------------------------------------------------------- mDNS ----

// The control panel's own record is always published so the operator can find
// the device at http://<hostname>.local/. The bait services are advertised too
// (when enabled) so the trap shows up on the LAN as the real thing — a file
// server, a DB box, a VNC host — rather than as a bare web server. That is what
// makes it discoverable to avahi-browse, Windows Network, and network scanners.
//
// Called at boot and again whenever the armed set, the toggle or the hostname
// changes, so the advertised records always match what the device is actually
// listening on. MDNS.begin() does not clear previously added records, so a
// re-apply tears the responder down first.
static bool s_mdnsStarted = false;

static void mdnsApply() {
  // Fully tear the responder down and start fresh, so a re-apply (hostname or
  // armed-set change) never accumulates duplicates. MDNS.end() also clears the
  // pre-registered records that IDF 5.x's mdns_init() may have added.
  if (s_mdnsStarted) {
    MDNS.end();
    s_mdnsStarted = false;
  }

  if (!MDNS.begin(g_cfg.hostname)) {
    Serial.println("[mdns] could not start mDNS responder");
    return;
  }
  s_mdnsStarted = true;

  // Re-applies can race the responder task of a *previous* instance if end()
  // wasn't fully drained; for each record make sure it isn't already there
  // before adding, and log if it still is.
  const auto ensureService = [](const char* type, const char* proto, uint16_t port) {
    if (mdns_service_exists(type, proto, nullptr)) {
      Serial.printf("[mdns] %s.%s already advertised — keeping existing\n", type, proto);
      return;
    }
    if (!MDNS.addService(type, proto, port)) {
      Serial.printf("[mdns] failed to advertise %s.%s on %u\n", type, proto, port);
    }
  };

  // The panel record is unconditional — without it the operator has no mDNS
  // way to find the device at all.
  ensureService("http", "tcp", 80);
  Serial.printf("[mdns] control panel at http://%s.local/\n", g_cfg.hostname);

  if (!g_cfg.mdnsAdvertise) {
    Serial.println("[mdns] bait service advertising is off");
    return;
  }

  size_t n = 0;
  const ServiceDef* cat = svcCatalogue(n);
  for (size_t i = 0; i < n; i++) {
    const ServiceDef& d = cat[i];
    if (!d.mdnsType || !cfgPortArmed(d.port)) continue;
    ensureService(d.mdnsType, "tcp", d.port);
    // TXT records are key=value pairs; the catalogue stores them as one
    // "u=root" string, split here for the ESPmDNS API.
    if (d.mdnsTxt) {
      const char* eq = strchr(d.mdnsTxt, '=');
      if (eq) {
        String key(d.mdnsTxt, eq - d.mdnsTxt);
        MDNS.addServiceTxt(d.mdnsType, "tcp", key.c_str(), eq + 1);
      }
    }
    Serial.printf("[mdns] advertising %s on %u\n", d.mdnsType, d.port);
  }
}

void webPump() { s_srv.handleClient(); }
