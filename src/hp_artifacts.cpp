#include "hp_artifacts.h"
#include "hp_config.h"
#include "hp_events.h"
#include <LittleFS.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <mbedtls/sha256.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

static const char* ART_DIR   = "/art";
static const char* ART_INDEX = "/artifacts.json";

static Artifact s_art[ART_MAX];
static uint8_t  s_count = 0;
static uint32_t s_bytes = 0;
static uint32_t s_fails = 0;
static QueueHandle_t s_q = nullptr;

struct Job { char url[200]; uint32_t ip; };

// ------------------------------------------------------------------ index ---

static String blobPath(const char* sha) {
  // 16 hex chars is 64 bits of the digest — collision-free for this scale and
  // it keeps the path short enough for every LittleFS build.
  return String(ART_DIR) + "/" + String(sha).substring(0, 16) + ".bin";
}

static void indexSave() {
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (uint8_t i = 0; i < s_count; i++) {
    JsonObject o = arr.add<JsonObject>();
    o["sha"]  = s_art[i].sha;
    o["url"]  = s_art[i].url;
    o["kind"] = s_art[i].kind;
    o["size"] = s_art[i].size;
    o["ts"]   = s_art[i].ts;
    o["ip"]   = s_art[i].ip;
    o["seen"] = s_art[i].seen;
  }
  File f = LittleFS.open(ART_INDEX, "w");
  if (!f) return;
  serializeJson(doc, f);
  f.close();
}

static void indexLoad() {
  File f = LittleFS.open(ART_INDEX, "r");
  if (!f) return;
  JsonDocument doc;
  bool ok = deserializeJson(doc, f) == DeserializationError::Ok;
  f.close();
  if (!ok) return;

  s_count = 0; s_bytes = 0;
  for (JsonObjectConst o : doc.as<JsonArrayConst>()) {
    if (s_count >= ART_MAX) break;
    Artifact& a = s_art[s_count];
    hpCopy(a.sha,  sizeof(a.sha),  o["sha"]  | "");
    hpCopy(a.url,  sizeof(a.url),  o["url"]  | "");
    hpCopy(a.kind, sizeof(a.kind), o["kind"] | "");
    // The defaults must be typed uint32_t. Writing `| 0` deduces int, and an
    // IPv4 in host byte order routinely exceeds INT32_MAX (192.168.8.213 is
    // 3574073557), so the stored value fails the int range check and silently
    // becomes 0 — losing exactly the attribution this record exists for.
    a.size = o["size"] | (uint32_t)0;
    a.ts   = o["ts"]   | (uint32_t)0;
    a.ip   = o["ip"]   | (uint32_t)0;
    a.seen = o["seen"] | (uint16_t)1;
    // Drop entries whose blob vanished, so the list never lies about what you
    // can actually download.
    if (!LittleFS.exists(blobPath(a.sha))) continue;
    s_bytes += a.size;
    s_count++;
  }
  Serial.printf("[art] %u samples on flash (%u bytes)\n", s_count, (unsigned)s_bytes);
}

static Artifact* findBySha(const char* sha) {
  for (uint8_t i = 0; i < s_count; i++) if (strcmp(s_art[i].sha, sha) == 0) return &s_art[i];
  return nullptr;
}

// Evicts the oldest sample to make room. Returns false if nothing can go.
static bool evictOldest() {
  if (!s_count) return false;
  uint8_t oldest = 0;
  for (uint8_t i = 1; i < s_count; i++) if (s_art[i].ts < s_art[oldest].ts) oldest = i;
  LittleFS.remove(blobPath(s_art[oldest].sha));
  s_bytes -= s_art[oldest].size;
  for (uint8_t i = oldest; i + 1 < s_count; i++) s_art[i] = s_art[i + 1];
  s_count--;
  return true;
}

// -------------------------------------------------------------- file type ---

// Reading the ELF header tells you which architecture the operator was aiming
// at, which is the single most informative thing about a captured dropper.
static void classify(const uint8_t* b, size_t n, char* out, size_t cap) {
  if (n >= 20 && b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
    const char* bits = b[4] == 2 ? "64-bit" : "32-bit";
    const char* endi = b[5] == 2 ? "MSB" : "LSB";
    uint16_t mach = (b[5] == 2) ? ((b[18] << 8) | b[19]) : (b[18] | (b[19] << 8));
    const char* arch;
    switch (mach) {
      case 0x03: arch = "x86";     break;
      case 0x3E: arch = "x86-64";  break;
      case 0x08: arch = "MIPS";    break;
      case 0x28: arch = "ARM";     break;
      case 0xB7: arch = "AArch64"; break;
      case 0x14: arch = "PowerPC"; break;
      case 0x2A: arch = "SuperH";  break;
      case 0xF3: arch = "RISC-V";  break;
      case 0x5E: arch = "Xtensa";  break;
      default:   arch = "unknown"; break;
    }
    snprintf(out, cap, "ELF %s %s %s", bits, endi, arch);
    return;
  }
  if (n >= 2 && b[0] == '#' && b[1] == '!')            { hpCopy(out, cap, "shell script"); return; }
  if (n >= 2 && b[0] == 'M' && b[1] == 'Z')            { hpCopy(out, cap, "PE executable"); return; }
  if (n >= 2 && b[0] == 0x1F && b[1] == 0x8B)          { hpCopy(out, cap, "gzip archive"); return; }
  if (n >= 4 && !memcmp(b, "PK\003\004", 4))           { hpCopy(out, cap, "zip archive"); return; }
  if (n >= 5 && !strncasecmp((const char*)b, "<?php", 5)) { hpCopy(out, cap, "PHP source"); return; }
  if (n >= 9 && !strncasecmp((const char*)b, "<!DOCTYPE", 9)) { hpCopy(out, cap, "HTML page"); return; }
  bool text = true;
  for (size_t i = 0; i < n && i < 64; i++) if (b[i] && (b[i] < 9 || (b[i] > 13 && b[i] < 32))) text = false;
  hpCopy(out, cap, text ? "text" : "binary data");
}

// ----------------------------------------------------------------- fetch ---

static bool fetchOne(const Job& job, String& err) {
  bool tls = strncmp(job.url, "https://", 8) == 0;

  WiFiClient plain;
  WiFiClientSecure secure;
  if (tls) secure.setInsecure();          // the point is the payload, not the cert

  HTTPClient http;
  http.setTimeout(9000);
  http.setConnectTimeout(6000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setUserAgent("Wget/1.20.3 (linux-gnu)");   // look like the tool they invoked

  if (!http.begin(tls ? (WiFiClient&)secure : plain, job.url)) {
    err = "URL could not be parsed";
    return false;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    err = "server replied " + String(code);
    http.end();
    return false;
  }

  const uint32_t cap = g_cfg.artMaxBytes;
  WiFiClient* stream = http.getStreamPtr();

  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0);

  String tmp = String(ART_DIR) + "/.incoming";
  LittleFS.remove(tmp);
  File out = LittleFS.open(tmp, "w");
  if (!out) { http.end(); mbedtls_sha256_free(&ctx); err = "no space on flash"; return false; }

  uint8_t  buf[512];
  uint8_t  head[24];
  size_t   headLen = 0;
  uint32_t total = 0;
  uint32_t idleStart = millis();
  bool     truncated = false;

  while (http.connected() && millis() - idleStart < 12000) {
    size_t avail = stream->available();
    if (!avail) {
      // -1 means chunked with unknown length; stop when the peer is done.
      if (http.getSize() >= 0 && total >= (uint32_t)http.getSize()) break;
      delay(5);
      continue;
    }
    int n = stream->readBytes(buf, avail > sizeof(buf) ? sizeof(buf) : avail);
    if (n <= 0) break;
    idleStart = millis();

    if (headLen < sizeof(head)) {
      size_t take = sizeof(head) - headLen;
      if ((size_t)n < take) take = n;
      memcpy(head + headLen, buf, take);
      headLen += take;
    }
    if (total + n > cap) { truncated = true; n = cap - total; }
    if (n > 0) {
      mbedtls_sha256_update_ret(&ctx, buf, n);
      out.write(buf, n);
      total += n;
    }
    if (truncated) break;
  }
  out.close();
  http.end();

  uint8_t digest[32];
  mbedtls_sha256_finish_ret(&ctx, digest);
  mbedtls_sha256_free(&ctx);

  if (!total) { LittleFS.remove(tmp); err = "server sent nothing"; return false; }
  if (truncated) {
    // A partial file has a meaningless hash — keep it out of the index rather
    // than record a digest that will never match anything.
    LittleFS.remove(tmp);
    err = "sample exceeds the " + String(cap / 1024) + " KB limit";
    return false;
  }

  char sha[65];
  for (uint8_t i = 0; i < 32; i++) snprintf(sha + i * 2, 3, "%02x", digest[i]);
  sha[64] = 0;

  Artifact* existing = findBySha(sha);
  if (existing) {
    existing->seen++;
    LittleFS.remove(tmp);
    indexSave();
    evLog(EV_DOWNLOAD, SEV_ALERT, job.ip, 23, "sample already held: %s (%s)",
          String(sha).substring(0, 16).c_str(), existing->kind);
    return true;
  }

  while ((s_count >= ART_MAX || s_bytes + total > g_cfg.artMaxBytes * 8) && evictOldest()) {}
  if (s_count >= ART_MAX) { LittleFS.remove(tmp); err = "sample store is full"; return false; }

  String dest = blobPath(sha);
  LittleFS.remove(dest);
  if (!LittleFS.rename(tmp, dest)) { LittleFS.remove(tmp); err = "could not store the sample"; return false; }

  Artifact& a = s_art[s_count++];
  memset(&a, 0, sizeof(a));
  hpCopy(a.sha, sizeof(a.sha), sha);
  hpCopy(a.url, sizeof(a.url), job.url);
  classify(head, headLen, a.kind, sizeof(a.kind));
  a.size = total;
  a.ip   = job.ip;
  a.seen = 1;
  time_t now = time(nullptr);
  a.ts = (now > 1700000000) ? (uint32_t)now : (millis() / 1000);
  s_bytes += total;
  indexSave();

  evLog(EV_DOWNLOAD, SEV_ALERT, job.ip, 23, "captured %s, %lu bytes, sha256 %s",
        a.kind, (unsigned long)total, String(sha).substring(0, 16).c_str());
  return true;
}

static void artTask(void*) {
  Job job;
  for (;;) {
    if (xQueueReceive(s_q, &job, portMAX_DELAY) != pdTRUE) continue;
    if (!g_cfg.collectArtifacts) continue;
    if (WiFi.status() != WL_CONNECTED) continue;

    String err;
    if (!fetchOne(job, err)) {
      s_fails++;
      evLog(EV_SYSTEM, SEV_NOTICE, job.ip, 0, "could not collect %s: %s",
            hpSanitize(job.url, 80).c_str(), err.c_str());
    }
  }
}

// ------------------------------------------------------------------- api ---

void artBegin() {
  if (!LittleFS.exists(ART_DIR)) LittleFS.mkdir(ART_DIR);
  // A partial download left by a power cut is worthless — drop it on boot.
  String tmp = String(ART_DIR) + "/.incoming";
  if (LittleFS.exists(tmp)) LittleFS.remove(tmp);
  indexLoad();
  s_q = xQueueCreate(6, sizeof(Job));
  // Modest priority and a generous stack: TLS needs room, but this task must
  // never outrank the honeypot listeners.
  xTaskCreatePinnedToCore(artTask, "hp_art", 12288, nullptr, 1, nullptr, 0);
}

void artQueue(const char* url, uint32_t ip) {
  if (!s_q || !g_cfg.collectArtifacts || !url) return;
  if (strncmp(url, "http://", 7) && strncmp(url, "https://", 8)) return;
  Job job{};
  hpCopy(job.url, sizeof(job.url), url);
  job.ip = ip;
  xQueueSend(s_q, &job, 0);
}

void artListJson(JsonArray out) {
  for (uint8_t i = 0; i < s_count; i++) {
    JsonObject o = out.add<JsonObject>();
    char ip[16];
    hpFormatIp(s_art[i].ip, ip, sizeof(ip));
    o["sha"]  = s_art[i].sha;
    o["url"]  = s_art[i].url;
    o["kind"] = s_art[i].kind;
    o["size"] = s_art[i].size;
    o["ts"]   = s_art[i].ts;
    o["ip"]   = ip;
    o["seen"] = s_art[i].seen;
  }
}

uint32_t artCount()    { return s_count; }
uint32_t artBytes()    { return s_bytes; }
uint32_t artFailures() { return s_fails; }

bool artStreamBlob(WebServer& srv, const String& sha) {
  Artifact* a = nullptr;
  for (uint8_t i = 0; i < s_count; i++) {
    if (sha.equalsIgnoreCase(s_art[i].sha)) { a = &s_art[i]; break; }
  }
  if (!a) return false;
  File f = LittleFS.open(blobPath(a->sha), "r");
  if (!f) return false;

  // Served as octet-stream with the digest as the filename, so a sample can
  // never be opened by accident and always names itself.
  srv.sendHeader("Content-Disposition",
                 "attachment; filename=\"" + String(a->sha) + ".sample\"");
  srv.streamFile(f, "application/octet-stream");
  f.close();
  return true;
}

void artClear() {
  for (uint8_t i = 0; i < s_count; i++) LittleFS.remove(blobPath(s_art[i].sha));
  LittleFS.remove(ART_INDEX);
  s_count = 0;
  s_bytes = 0;
}
