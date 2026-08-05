#pragma once
#include <Arduino.h>
// Arduino's Print, reduced to what the firmware calls.
class Print {
 public:
  virtual ~Print() {}
  virtual size_t write(uint8_t c) = 0;
  size_t write(const uint8_t* b, size_t n) { for (size_t i = 0; i < n; i++) write(b[i]); return n; }
  size_t print(const char* p) { size_t n = 0; while (p && *p) { write((uint8_t)*p++); n++; } return n; }
  size_t print(const String& s) { return print(s.c_str()); }
  size_t print(char c) { return write((uint8_t)c); }
  size_t println(const char* p) { return print(p) + print("\r\n"); }
  size_t println(const String& s) { return println(s.c_str()); }
  size_t printf(const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return 0;
    return print(buf);
  }
};
