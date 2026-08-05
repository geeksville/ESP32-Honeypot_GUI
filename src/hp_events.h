#pragma once
#include "hp_common.h"
#include <ArduinoJson.h>

// Allocates the in-RAM event ring (PSRAM when the board has it) and clears
// statistics. Call once, before any task that logs.
void evBegin();

// Records an event: pushes it to the ring, updates stats, queues a webhook and
// appends to flash. Safe to call from any task. Returns the assigned sequence.
uint32_t evLog(uint8_t kind, uint8_t sev, uint32_t ip, uint16_t port,
               const char* fmt, ...) __attribute__((format(printf, 5, 6)));

// Copies up to `max` events newer than `cursor` into `out`, oldest first.
// `outCursor` receives the sequence the caller should ask from next time.
size_t evSince(uint32_t cursor, Event* out, size_t max, uint32_t* outCursor);

uint32_t evLatestSeq();
uint32_t evRingCapacity();

void evStatsJson(JsonObject o);
void evClearStats();

// Human-readable names, shared with the export path and the UI.
const char* evKindName(uint8_t k);
const char* evSevName(uint8_t s);
