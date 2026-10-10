// Shared types for the honeypot. Everything here is POD so events can live in
// a fixed-stride ring buffer (optionally in PSRAM) without heap churn.
#pragma once
#include <Arduino.h>

#ifndef HP_VERSION
#define HP_VERSION "2.0.0-dev"
#endif

// ---------------------------------------------------------------- events ---

// What happened. Kept narrow on purpose: the UI groups by these.
enum EventKind : uint8_t {
  EV_CONNECT = 0,   // TCP session opened on a baited port
  EV_PROBE,         // raw bytes sent to a banner-only port
  EV_LOGIN,         // credentials offered to the telnet shell
  EV_COMMAND,       // command typed into the fake shell
  EV_DOWNLOAD,      // wget/curl/tftp — a malware dropper URL
  EV_DISCONNECT,
  EV_SYSTEM,        // boot, wifi, config change
  EV_KIND_COUNT
};

// How much you should care. Drives colour in the UI and webhook filtering.
enum Severity : uint8_t {
  SEV_INFO = 0,     // someone knocked
  SEV_NOTICE,       // someone is poking around
  SEV_ALERT         // any probe, credential theft, dropper URL, botnet signature
};

static const uint8_t HP_DETAIL_LEN = 168;

struct Event {
  uint32_t seq;              // monotonic since boot, the UI's polling cursor
  uint32_t ts;               // unix epoch, 0 until NTP lands
  uint32_t uptimeMs;
  uint32_t ip;               // IPv4, host byte order
  uint16_t port;
  uint8_t  kind;
  uint8_t  severity;
  char     detail[HP_DETAIL_LEN];
};

// ---------------------------------------------------------------- config ---

// Socket budget. lwIP is compiled into the Arduino core with
// CONFIG_LWIP_MAX_SOCKETS=16 and it cannot be raised without rebuilding the
// IDF, so every listener spent is a socket unavailable to an accepted
// connection:
//
//     8 honeypot listeners + 1 web listener + 6 live connections + 1 spare = 16
//
// Exceed it and accept() starts failing, which a scanner reports as
// "tcpwrapped" on every port — the most obvious tell a honeypot can give.
static const uint8_t  HP_MAX_PORTS   = 8;
static const uint8_t  HP_STR         = 96;   // ssid, passwords, hostnames
static const uint16_t HP_URL         = 256;  // webhook URLs get long

enum PanelAccess : uint8_t {
  PANEL_AP_ONLY = 0,   // reachable only by joining the device's own network
  PANEL_PRIVATE,       // + RFC1918 / link-local sources  (default)
  PANEL_ANYWHERE       // explicit opt-in, including the public internet
};

enum NotifyMode : uint8_t {
  NOTIFY_OFF = 0,
  NOTIFY_DISCORD,
  NOTIFY_TELEGRAM,
  NOTIFY_GENERIC,   // raw JSON POST, for SIEM ingest
  NOTIFY_SYSLOG     // RFC 5424 over UDP
};

struct AppConfig {
  char     ssid[HP_STR];
  char     wifiPass[HP_STR];
  char     adminPass[HP_STR];      // empty = unauthenticated UI (warned about)

  uint16_t ports[HP_MAX_PORTS];    // armed bait ports
  uint8_t  portCount;

  uint8_t  notifyMode;
  char     notifyUrl[HP_URL];      // webhook URL, or syslog host
  char     notifyExtra[HP_STR];    // telegram chat id / syslog port
  uint8_t  notifyMinSeverity;      // don't page me for a port scan
  uint16_t notifyCooldownS;        // floor between outbound alerts

  char     hostname[HP_STR];       // what the fake shell calls itself
  char     shellUser[HP_STR];      // and who you're logged in as
  char     tz[HP_STR];             // POSIX TZ string

  bool     alwaysAp;               // keep the setup AP up alongside the LAN
  bool     logToFlash;

  // Advertise the bait services over mDNS (Bonjour/Avahi) so the trap shows up
  // on the LAN as the real thing — a file server, a DB box, etc. The control
  // panel's own _http._tcp record is always published so the operator can find
  // the device; this only controls the bait-port records.
  bool     mdnsAdvertise;

  // Where the control panel may be reached from. The bait ports are meant to
  // face the internet; the panel is not, and forwarding port 80 by accident
  // should not hand over the device. Enforced on every request by source
  // address, and forced to PANEL_AP_ONLY while no panel password is set.
  uint8_t  panelAccess;

  // Retrieving a dropper reveals to its operator that this address is live, so
  // this stays off until the operator turns it on deliberately.
  bool     collectArtifacts;
  uint32_t artMaxBytes;            // per-sample ceiling

  // LAN-only mode. The bait ports answer private sources and ignore everything
  // else, turning the device into an internal canary: anything that touches it
  // is already inside the network, so every hit is signal rather than the
  // constant background scanning a public address attracts.
  bool     lanOnly;
};

// ------------------------------------------------------------------ misc ---

// True for RFC1918, loopback, link-local and CGNAT space. Takes an IPv4 in the
// host byte order WiFiClient::remoteIP() produces.
bool hpIsPrivateV4(uint32_t ip);

// Formats an IPv4 in host byte order into "192.168.1.5".
void hpFormatIp(uint32_t ip, char* out, size_t len);

// Copies src into a fixed char[] and always terminates. Returns true if it fit.
bool hpCopy(char* dst, size_t cap, const char* src);

// Replaces bytes that would break a log line or a JSON string with a visible
// escape, so captured attacker input can never corrupt our own output.
String hpSanitize(const String& in, size_t maxLen);
