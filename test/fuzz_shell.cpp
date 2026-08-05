// Fuzz target for the telnet shell emulator.
//
// This is the largest attacker-reachable parsing surface in the firmware:
// command dispatch, path resolution, the fake filesystem lookup, ls flag
// parsing and dropper-URL extraction all run on bytes an attacker chose.
//
//   clang++ -fsanitize=fuzzer,address,undefined ... test/fuzz_shell.cpp
//
// Including the .cpp rather than the header makes its static functions
// reachable, so vfsResolve and extractUrl can be driven directly.
#include <Arduino.h>
#include <Print.h>
#include "../src/hp_common.h"
#include "../src/hp_config.h"
#include "../src/hp_events.h"
#include "../src/hp_artifacts.h"

// ---- environment the firmware expects -------------------------------------
AppConfig g_cfg;
static unsigned long g_millis = 0;
unsigned long millis() { return g_millis += 7; }

uint32_t evLog(uint8_t, uint8_t, uint32_t, uint16_t, const char* fmt, ...) {
  // Exercise the same formatting path the device uses, into the same-sized
  // buffer, so a format-string or truncation bug still shows up here.
  char detail[HP_DETAIL_LEN];
  va_list ap; va_start(ap, fmt);
  vsnprintf(detail, sizeof(detail), fmt, ap);
  va_end(ap);
  return 0;
}
void artQueue(const char*, uint32_t) {}

// Swallows shell output; we care about crashes, not content.
class NullPrint : public Print {
 public:
  size_t bytes = 0;
  size_t write(uint8_t) override { bytes++; return 1; }
};

#include "../src/hp_shell.cpp"
#include "../src/hp_util.cpp"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  memset(&g_cfg, 0, sizeof(g_cfg));
  hpCopy(g_cfg.hostname,  HP_STR, "srv-fileshare");
  hpCopy(g_cfg.shellUser, HP_STR, "admin");
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0 || size > 8192) return 0;

  ShellSession sh;
  shellReset(sh);
  NullPrint out;

  // Treat the input as a session transcript: newline-separated lines fed in
  // order, exactly as pumpTelnet would deliver them.
  String line;
  for (size_t i = 0; i < size; i++) {
    char c = (char)data[i];
    if (c == '\n') {
      if (!shellFeedLine(sh, line, out, 0x0100007f)) break;
      line = String();
      continue;
    }
    if (line.length() < 512) line += c;
  }
  if (line.length()) shellFeedLine(sh, line, out, 0x0100007f);

  // Drive the two hand-rolled parsers directly as well.
  String raw((const char*)std::string((const char*)data, size).c_str());
  vfsResolve("/home/admin", raw);
  vfsResolve(raw, "..");
  extractUrl(raw);
  hpSanitize(raw, 120);
  return 0;
}
