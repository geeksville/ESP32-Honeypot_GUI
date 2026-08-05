#pragma once
#include "hp_common.h"
#include <ArduinoJson.h>

extern AppConfig g_cfg;

void cfgSetDefaults(AppConfig& c);
bool cfgLoad();                       // false if absent/corrupt (defaults kept)
bool cfgSave();
void cfgReset();                      // wipe to defaults and persist

// Applies a JSON patch. Only keys present are touched, so the UI can PATCH a
// single field. `err` gets a user-facing reason on failure.
// `lenient` truncates an over-long port list instead of rejecting the whole
// config — used when loading from flash, never for API input.
bool cfgApplyJson(JsonObjectConst in, String& err, bool lenient = false);

// Serialises for the UI. Secrets are replaced with a sentinel unless
// `includeSecrets` — the Wi-Fi password must never leave the device.
void cfgToJson(JsonObject out, bool includeSecrets = false);

bool cfgPortArmed(uint16_t port);

// The sentinel the UI sends back for "leave this password alone".
static const char* CFG_SECRET_KEEP = "\x01keep";
