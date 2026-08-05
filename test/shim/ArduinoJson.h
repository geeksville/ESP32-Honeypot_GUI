#pragma once
// Type-only stub. The fuzz targets never serialise; these exist so the firmware
// headers that mention them will compile natively.
struct JsonObject {}; struct JsonObjectConst {}; struct JsonArray {};
struct JsonArrayConst {}; struct JsonVariantConst {}; struct JsonDocument {};
