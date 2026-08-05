#pragma once
#include "hp_common.h"

// Mounts LittleFS, migrating a v1 SPIFFS config across if one is found.
// Returns false only if the flash partition is unusable.
bool storeBegin();

// Appends one NDJSON record, rotating when the live file gets large. Rotation
// keeps exactly one previous generation, so flash use has a hard ceiling and
// the honeypot can never go deaf because the log filled up.
void storeAppendEvent(const Event& e);

size_t storeLogSize();
size_t storeFsUsed();
size_t storeFsTotal();
void   storeClearLog();

// Streams the captured events straight from flash to an HTTP client, so a
// multi-megabyte log never has to fit in RAM. `asCsv` converts on the fly.
class WiFiClient;
void storeStreamLog(class WebServer& srv, bool asCsv);

constexpr const char* LOG_PATH  = "/events.ndjson";
constexpr const char* LOG_PREV  = "/events.1.ndjson";
