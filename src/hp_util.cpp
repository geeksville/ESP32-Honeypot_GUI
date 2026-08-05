#include "hp_common.h"

void hpFormatIp(uint32_t ip, char* out, size_t len) {
  snprintf(out, len, "%u.%u.%u.%u",
           (unsigned)(ip & 0xFF), (unsigned)((ip >> 8) & 0xFF),
           (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 24) & 0xFF));
}

bool hpIsPrivateV4(uint32_t ip) {
  const uint8_t a = ip & 0xFF, b = (ip >> 8) & 0xFF;
  return a == 10
      || (a == 172 && b >= 16 && b <= 31)
      || (a == 192 && b == 168)
      || a == 127
      || (a == 169 && b == 254)
      || (a == 100 && b >= 64 && b <= 127);
}

bool hpCopy(char* dst, size_t cap, const char* src) {
  if (!src) { dst[0] = 0; return true; }
  size_t n = strlen(src);
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = 0;
  return n < cap;
}

String hpSanitize(const String& in, size_t maxLen) {
  String out;
  out.reserve(in.length() < maxLen ? in.length() : maxLen);
  for (size_t i = 0; i < in.length() && out.length() < maxLen; i++) {
    unsigned char c = (unsigned char)in[i];
    // Anything a terminal, a log tail or a JSON parser could misread becomes a
    // dot. Attackers do send escape sequences hoping the operator's terminal
    // will act on them.
    out += (c >= 0x20 && c != 0x7F) ? (char)c : '.';
  }
  out.trim();
  return out;
}
