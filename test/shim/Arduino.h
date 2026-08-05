// Minimal Arduino compatibility layer for building firmware logic natively.
//
// String deliberately mirrors the ESP32 core's *defensive* semantics: it clamps
// out-of-range indices and returns 0 / -1 / "" rather than faulting. Using
// std::string semantics here instead would make the fuzzer report crashes that
// cannot occur on the device.
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <cstdarg>
#include <string>

typedef uint8_t byte;

class String {
  std::string s;
 public:
  String() {}
  String(const char* p) : s(p ? p : "") {}
  String(const std::string& o) : s(o) {}
  String(char c) : s(1, c) {}
  String(int v)           { char b[24]; snprintf(b, sizeof(b), "%d", v);   s = b; }
  String(unsigned v)      { char b[24]; snprintf(b, sizeof(b), "%u", v);   s = b; }
  String(long v)          { char b[24]; snprintf(b, sizeof(b), "%ld", v);  s = b; }
  String(unsigned long v) { char b[24]; snprintf(b, sizeof(b), "%lu", v);  s = b; }

  unsigned length() const { return (unsigned)s.size(); }
  const char* c_str() const { return s.c_str(); }
  void reserve(unsigned n) { s.reserve(n); }

  // Matches WString.cpp: swaps reversed bounds, empty if left past the end,
  // right clamped to length.
  String substring(unsigned left, unsigned right) const {
    if (left > right) { unsigned t = right; right = left; left = t; }
    if (left >= length()) return String();
    if (right > length()) right = length();
    return String(s.substr(left, right - left));
  }
  String substring(unsigned left) const { return substring(left, length()); }

  int indexOf(char c, unsigned from = 0) const {
    if (from >= length()) return -1;
    size_t p = s.find(c, from);
    return p == std::string::npos ? -1 : (int)p;
  }
  int indexOf(const char* n, unsigned from = 0) const {
    if (from >= length()) return -1;
    size_t p = s.find(n, from);
    return p == std::string::npos ? -1 : (int)p;
  }
  int indexOf(const String& n, unsigned from = 0) const { return indexOf(n.c_str(), from); }
  int lastIndexOf(char c) const {
    size_t p = s.rfind(c);
    return p == std::string::npos ? -1 : (int)p;
  }
  bool startsWith(const String& p) const { return s.rfind(p.s, 0) == 0; }
  bool startsWith(const char* p) const   { return s.rfind(p, 0) == 0; }
  bool endsWith(const String& p) const {
    return s.size() >= p.s.size() && s.compare(s.size() - p.s.size(), p.s.size(), p.s) == 0;
  }
  bool endsWith(const char* p) const { return endsWith(String(p)); }
  bool equals(const String& o) const { return s == o.s; }

  void trim() {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) { s.clear(); return; }
    size_t e = s.find_last_not_of(" \t\r\n");
    s = s.substr(b, e - b + 1);
  }
  void remove(unsigned idx, unsigned cnt = 0xFFFFFFFFu) {
    if (idx >= length()) return;
    if (cnt > length() - idx) cnt = length() - idx;
    s.erase(idx, cnt);
  }
  void replace(const String& f, const String& r) {
    if (f.s.empty()) return;
    size_t p = 0;
    while ((p = s.find(f.s, p)) != std::string::npos) { s.replace(p, f.s.size(), r.s); p += r.s.size(); }
  }
  void replace(const char* f, const char* r) { replace(String(f), String(r)); }
  void toUpperCase() { for (auto& c : s) c = toupper((unsigned char)c); }
  void toLowerCase() { for (auto& c : s) c = tolower((unsigned char)c); }

  char operator[](unsigned i) const { return i >= length() ? 0 : s[i]; }
  char charAt(unsigned i) const { return operator[](i); }

  String& operator+=(const String& o) { s += o.s; return *this; }
  String& operator+=(const char* o)   { s += (o ? o : ""); return *this; }
  String& operator+=(char c)          { s += c; return *this; }
  friend String operator+(String a, const String& b) { a += b; return a; }
  friend String operator+(String a, const char* b)   { a += b; return a; }
  friend String operator+(const char* a, const String& b) { return String(a) + b; }
  bool operator==(const String& o) const { return s == o.s; }
  bool operator==(const char* o)   const { return s == (o ? o : ""); }
  bool operator!=(const String& o) const { return !(*this == o); }
  bool operator!=(const char* o)   const { return !(*this == o); }
};

unsigned long millis();
