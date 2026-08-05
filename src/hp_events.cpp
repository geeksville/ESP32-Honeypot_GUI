#include "hp_events.h"
#include "hp_config.h"
#include "hp_store.h"
#include "hp_notify.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// The ring is what the dashboard reads, so it should hold enough history to be
// useful without a flash read on every poll. With PSRAM we can afford a lot.
static const uint16_t RING_PSRAM = 2048;
static const uint16_t RING_HEAP  = 128;

static Event*   s_ring     = nullptr;
static uint16_t s_ringCap  = 0;
static uint16_t s_ringHead = 0;      // next write slot
static uint32_t s_nextSeq  = 1;
static SemaphoreHandle_t s_lock = nullptr;

// -------------------------------------------------------------- stat bins ---

static const uint8_t MAX_PORT_BINS = 20;
static const uint8_t MAX_IP_BINS   = 32;
static const uint8_t MAX_CRED_BINS = 16;

struct PortBin { uint16_t port; uint32_t hits; };
struct IpBin   { uint32_t ip; uint32_t hits; uint32_t firstUp, lastUp; uint8_t worstSev; };
struct CredBin { char cred[48]; uint32_t hits; };

static PortBin s_ports[MAX_PORT_BINS];
static IpBin   s_ips[MAX_IP_BINS];
static CredBin s_creds[MAX_CRED_BINS];
static uint32_t s_kindTotals[EV_KIND_COUNT];
static uint32_t s_sevTotals[3];
static uint32_t s_total;

// Rolling 24 h histogram. Each slot remembers which absolute hour it holds so
// a quiet device doesn't show week-old counts as if they were from today.
static uint32_t s_hourCount[24];
static uint32_t s_hourStamp[24];

static const char* KIND_NAMES[EV_KIND_COUNT] = {
  "connect", "probe", "login", "command", "download", "disconnect", "system"
};
static const char* SEV_NAMES[3] = {"info", "notice", "alert"};

const char* evKindName(uint8_t k) { return k < EV_KIND_COUNT ? KIND_NAMES[k] : "?"; }
const char* evSevName(uint8_t s)  { return s < 3 ? SEV_NAMES[s] : "?"; }

// ------------------------------------------------------------------ init ---

void evBegin() {
  s_lock = xSemaphoreCreateMutex();

#if defined(BOARD_HAS_PSRAM)
  if (psramFound()) {
    s_ring = (Event*)ps_calloc(RING_PSRAM, sizeof(Event));
    if (s_ring) s_ringCap = RING_PSRAM;
  }
#endif
  if (!s_ring) {
    s_ring = (Event*)calloc(RING_HEAP, sizeof(Event));
    s_ringCap = s_ring ? RING_HEAP : 0;
  }
  Serial.printf("[events] ring holds %u events (%u bytes, %s)\n",
                s_ringCap, (unsigned)(s_ringCap * sizeof(Event)),
                s_ringCap == RING_PSRAM ? "PSRAM" : "heap");
  evClearStats();
}

void evClearStats() {
  memset(s_ports, 0, sizeof(s_ports));
  memset(s_ips, 0, sizeof(s_ips));
  memset(s_creds, 0, sizeof(s_creds));
  memset(s_kindTotals, 0, sizeof(s_kindTotals));
  memset(s_sevTotals, 0, sizeof(s_sevTotals));
  memset(s_hourCount, 0, sizeof(s_hourCount));
  memset(s_hourStamp, 0xFF, sizeof(s_hourStamp));
  s_total = 0;
}

// ----------------------------------------------------------------- tally ---

static void tallyPort(uint16_t port) {
  for (uint8_t i = 0; i < MAX_PORT_BINS; i++) {
    if (s_ports[i].port == port) { s_ports[i].hits++; return; }
    if (s_ports[i].port == 0)    { s_ports[i].port = port; s_ports[i].hits = 1; return; }
  }
}

static void tallyIp(uint32_t ip, uint8_t sev, uint32_t up) {
  if (!ip) return;
  uint8_t coldest = 0;
  for (uint8_t i = 0; i < MAX_IP_BINS; i++) {
    if (s_ips[i].ip == ip) {
      s_ips[i].hits++;
      s_ips[i].lastUp = up;
      if (sev > s_ips[i].worstSev) s_ips[i].worstSev = sev;
      return;
    }
    if (s_ips[i].ip == 0) {
      s_ips[i] = {ip, 1, up, up, sev};
      return;
    }
    // Evict the least interesting: fewest hits, oldest activity as tiebreak.
    if (s_ips[i].hits < s_ips[coldest].hits ||
        (s_ips[i].hits == s_ips[coldest].hits && s_ips[i].lastUp < s_ips[coldest].lastUp)) {
      coldest = i;
    }
  }
  s_ips[coldest] = {ip, 1, up, up, sev};
}

static void tallyCred(const char* cred) {
  uint8_t coldest = 0;
  for (uint8_t i = 0; i < MAX_CRED_BINS; i++) {
    if (s_creds[i].hits && strcmp(s_creds[i].cred, cred) == 0) { s_creds[i].hits++; return; }
    if (!s_creds[i].hits) {
      hpCopy(s_creds[i].cred, sizeof(s_creds[i].cred), cred);
      s_creds[i].hits = 1;
      return;
    }
    if (s_creds[i].hits < s_creds[coldest].hits) coldest = i;
  }
  hpCopy(s_creds[coldest].cred, sizeof(s_creds[coldest].cred), cred);
  s_creds[coldest].hits = 1;
}

static void tallyHour(uint32_t ts) {
  if (!ts) return;
  uint32_t absHour = ts / 3600;
  uint8_t  slot    = absHour % 24;
  if (s_hourStamp[slot] != absHour) { s_hourStamp[slot] = absHour; s_hourCount[slot] = 0; }
  s_hourCount[slot]++;
}

// ------------------------------------------------------------------- log ---

uint32_t evLog(uint8_t kind, uint8_t sev, uint32_t ip, uint16_t port,
               const char* fmt, ...) {
  Event e{};
  e.kind     = kind;
  e.severity = sev;
  e.ip       = ip;
  e.port     = port;
  e.uptimeMs = millis();
  time_t now = time(nullptr);
  e.ts       = (now > 1700000000) ? (uint32_t)now : 0;   // 0 until NTP lands

  va_list ap;
  va_start(ap, fmt);
  vsnprintf(e.detail, HP_DETAIL_LEN, fmt, ap);
  va_end(ap);

  // Attacker-controlled bytes reach us here. Strip anything that could break a
  // log line, a JSON string, or a terminal that later tails the file.
  for (char* p = e.detail; *p; ++p) {
    if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7F) *p = '.';
  }

  if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY);
  e.seq = s_nextSeq++;
  if (s_ringCap) {
    s_ring[s_ringHead] = e;
    s_ringHead = (s_ringHead + 1) % s_ringCap;
  }
  s_total++;
  if (kind < EV_KIND_COUNT) s_kindTotals[kind]++;
  if (sev < 3) s_sevTotals[sev]++;
  if (kind != EV_SYSTEM) { tallyPort(port); tallyIp(ip, sev, e.uptimeMs); }
  tallyHour(e.ts);
  // Scanners fire HTTP/SIP/RTSP request lines at port 23, and the shell dutifully
  // reads them as a username. They belong in the event log but not in a ranking
  // of what credentials people are guessing with.
  bool protocolNoise = strstr(e.detail, " HTTP/") || strstr(e.detail, " SIP/") ||
                       strstr(e.detail, " RTSP/");
  if (kind == EV_LOGIN && !protocolNoise) tallyCred(e.detail);
  uint32_t seq = e.seq;
  if (s_lock) xSemaphoreGive(s_lock);

  char ipStr[16];
  hpFormatIp(ip, ipStr, sizeof(ipStr));
  Serial.printf("[%-6s] %-15s :%-5u %s\n", evSevName(sev), ipStr, port, e.detail);

  storeAppendEvent(e);
  notifyQueue(e);
  return seq;
}

size_t evSince(uint32_t cursor, Event* out, size_t max, uint32_t* outCursor) {
  size_t n = 0;
  if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY);
  if (s_ringCap) {
    // Walk oldest to newest so the caller can append without re-sorting.
    for (uint16_t i = 0; i < s_ringCap && n < max; i++) {
      const Event& e = s_ring[(s_ringHead + i) % s_ringCap];
      if (e.seq && e.seq > cursor) out[n++] = e;
    }
  }
  if (outCursor) *outCursor = n ? out[n - 1].seq : (s_nextSeq - 1);
  if (s_lock) xSemaphoreGive(s_lock);
  return n;
}

uint32_t evLatestSeq()     { return s_nextSeq - 1; }
uint32_t evRingCapacity()  { return s_ringCap; }

// ----------------------------------------------------------------- stats ---

void evStatsJson(JsonObject o) {
  if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY);

  o["total"] = s_total;

  JsonObject kinds = o["kinds"].to<JsonObject>();
  for (uint8_t i = 0; i < EV_KIND_COUNT; i++) kinds[KIND_NAMES[i]] = s_kindTotals[i];

  JsonObject sevs = o["severity"].to<JsonObject>();
  for (uint8_t i = 0; i < 3; i++) sevs[SEV_NAMES[i]] = s_sevTotals[i];

  JsonObject ports = o["ports"].to<JsonObject>();
  for (uint8_t i = 0; i < MAX_PORT_BINS && s_ports[i].port; i++) {
    ports[String(s_ports[i].port)] = s_ports[i].hits;
  }

  JsonArray ips = o["visitors"].to<JsonArray>();
  for (uint8_t i = 0; i < MAX_IP_BINS && s_ips[i].ip; i++) {
    JsonObject v = ips.add<JsonObject>();
    char ipStr[16];
    hpFormatIp(s_ips[i].ip, ipStr, sizeof(ipStr));
    v["ip"]    = ipStr;
    v["hits"]  = s_ips[i].hits;
    v["sev"]   = s_ips[i].worstSev;
    v["agoMs"] = millis() - s_ips[i].lastUp;
  }

  JsonArray creds = o["creds"].to<JsonArray>();
  for (uint8_t i = 0; i < MAX_CRED_BINS && s_creds[i].hits; i++) {
    JsonObject c = creds.add<JsonObject>();
    c["v"] = s_creds[i].cred;
    c["n"] = s_creds[i].hits;
  }

  // Emit the histogram oldest-first relative to the current hour, so the UI can
  // render it left-to-right without knowing about the wrap.
  time_t now = time(nullptr);
  uint32_t curHour = (now > 1700000000) ? (uint32_t)now / 3600 : 0;
  JsonArray hours = o["hours"].to<JsonArray>();
  for (int8_t back = 23; back >= 0; back--) {
    uint32_t absHour = curHour - back;
    uint8_t slot = absHour % 24;
    hours.add((curHour && s_hourStamp[slot] == absHour) ? s_hourCount[slot] : 0);
  }

  if (s_lock) xSemaphoreGive(s_lock);
}
