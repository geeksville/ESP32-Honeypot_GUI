#pragma once
#include "hp_common.h"
#include <ArduinoJson.h>

// How a port behaves once something connects.
enum SvcKind : uint8_t {
  SVC_BANNER = 0,   // binary greeting, record what they say, hang up
  SVC_TELNET,       // full interactive shell
  SVC_SSH,          // banner, then hold open so nmap finishes its key probe
  SVC_HTTP,         // read the request line, answer as Apache
  SVC_DNS,          // answer a version.bind CHAOS query over TCP
  // Line protocols that hold a conversation. Answering commands instead of
  // hanging up is what stops nmap reporting "tcpwrapped", and it is also the
  // only way these ports ever capture a credential.
  SVC_FTP,
  SVC_SMTP,
  SVC_POP3,
  SVC_IMAP,
  SVC_REDIS
};

struct ServiceDef {
  uint16_t       port;
  const char*    name;      // "SSH"
  const char*    product;   // "OpenSSH 8.9p1 Ubuntu"
  const char*    preview;   // printable form of the banner, for the UI
  SvcKind        kind;
  const uint8_t* banner;
  uint16_t       bannerLen;
};

// The full catalogue, including ports not armed by default.
const ServiceDef* svcCatalogue(size_t& count);
const ServiceDef* svcFind(uint16_t port);

// (Re)opens listeners to match the armed set in g_cfg. Safe to call at runtime;
// closing a port drops its listener without disturbing the others.
void svcApplyConfig();

// Accepts new connections and pumps existing ones. Never blocks. Call often.
void svcPump();

uint8_t svcActiveConnections();

// Bumped whenever the armed set changes. The catalogue is ~70% of a status poll
// and is otherwise identical every time, so the client caches it and only asks
// again when this moves.
uint32_t svcCatalogueVersion();

// Includes the catalogue only when `knownVersion` is stale.
void svcStatusJson(JsonObject out, uint32_t knownVersion);
