// Non-blocking multi-port listener.
//
// v1 handled one client at a time inside a while(true) that never returned from
// setup(), and read from sockets with a spin loop that had no timeout — a single
// connection that opened and said nothing took every port offline. Here every
// connection is a slot in a fixed pool, each pumped for a few microseconds per
// pass, with idle and absolute deadlines.
#include "hp_services.h"
#include "hp_config.h"
#include "hp_events.h"
#include "hp_shell.h"
#include <WiFi.h>

// ------------------------------------------------------------- catalogue ---

static const uint8_t B_FTP[]    = "220 ProFTPD Server (Debian) [::ffff:10.20.4.11]\r\n";
static const uint8_t B_SSH[]    = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5\r\n";
static const uint8_t B_SMTP[]   = "220 mail.corp.local ESMTP Postfix (Ubuntu)\r\n";
static const uint8_t B_POP3[]   = "+OK Dovecot (Ubuntu) ready.\r\n";
static const uint8_t B_IMAP[]   = "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+] Dovecot (Ubuntu) ready.\r\n";
static const uint8_t B_VNC[]    = "RFB 003.008\n";
static const uint8_t B_REDIS[]  = "-DENIED Redis is running in protected mode\r\n";

// MySQL 8.0 initial handshake. The 4-byte header carries the payload length in
// 3 little-endian bytes plus a sequence id, which v1 got wrong for SMB/MySQL.
static const uint8_t B_MYSQL[] = {
  0x4a, 0x00, 0x00, 0x00,                             // length 74, seq 0
  0x0a,                                               // protocol 10
  '8','.','0','.','3','5','-','0','u','b','u','n','t','u','0','.','2','2','.','0','4','.','1', 0x00,
  0x0b, 0x00, 0x00, 0x00,                             // connection id
  'K','7','#','q','R','2','v','P', 0x00,              // auth-plugin-data part 1
  0xff, 0xff,                                         // capability flags lower
  0xff,                                               // charset utf8mb4
  0x02, 0x00,                                         // status flags
  0xff, 0xdf,                                         // capability flags upper
  0x15,                                               // auth-plugin-data len
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  // reserved
  'x','L','9','m','B','4','w','Z','2','n','Q','1', 0x00,
  'c','a','c','h','i','n','g','_','s','h','a','2','_','p','a','s','s','w','o','r','d', 0x00
};

// SMB negotiate response with a correct NetBIOS length prefix.
static const uint8_t B_SMB[] = {
  0x00, 0x00, 0x00, 0x55,
  0xff, 'S', 'M', 'B', 0x72, 0x00, 0x00, 0x00, 0x00,
  0x98, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x11, 0x05, 0x00, 0x03, 0x0a,
  0x00, 0x01, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xe3, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// X.224 Connection Confirm — what a real RDP listener answers a scan with.
static const uint8_t B_RDP[] = {
  0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00,
  0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00,
  0x00, 0x00, 0x00
};

static const ServiceDef CATALOGUE[] = {
  {   21, "FTP",     "ProFTPD 1.3.8 (Debian)",   "220 ProFTPD Server (Debian)",              SVC_FTP,    B_FTP,   sizeof(B_FTP) - 1},
  {   22, "SSH",     "OpenSSH 8.9p1 Ubuntu",     "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5",  SVC_SSH,    B_SSH,   sizeof(B_SSH) - 1},
  {   23, "Telnet",  "Linux telnetd",            "Interactive Ubuntu 22.04 shell",           SVC_TELNET, nullptr, 0},
  {   25, "SMTP",    "Postfix (Ubuntu)",         "220 mail.corp.local ESMTP Postfix",        SVC_SMTP,   B_SMTP,  sizeof(B_SMTP) - 1},
  {   53, "DNS",     "ISC BIND 9.18.18",         "CHAOS TXT version.bind → 9.18.18",         SVC_DNS,    nullptr, 0},
  {  110, "POP3",    "Dovecot pop3d",            "+OK Dovecot (Ubuntu) ready.",              SVC_POP3,   B_POP3,  sizeof(B_POP3) - 1},
  {  143, "IMAP",    "Dovecot imapd",            "* OK [CAPABILITY IMAP4rev1 …] Dovecot",    SVC_IMAP,   B_IMAP,  sizeof(B_IMAP) - 1},
  {  443, "HTTPS",   "Apache 2.4.52 (Ubuntu)",   "HTTP/1.1 200 — Apache/2.4.52 (Ubuntu)",    SVC_HTTP,   nullptr, 0},
  {  445, "SMB",     "Samba 4.15.13 (Ubuntu)",   "SMB negotiate response",                   SVC_BANNER, B_SMB,   sizeof(B_SMB)},
  { 3306, "MySQL",   "MySQL 8.0.35-0ubuntu0.22", "8.0.35-0ubuntu0.22.04.1 handshake",        SVC_BANNER, B_MYSQL, sizeof(B_MYSQL)},
  { 3389, "RDP",     "Microsoft Terminal Svc",   "X.224 Connection Confirm",                 SVC_BANNER, B_RDP,   sizeof(B_RDP)},
  { 5900, "VNC",     "RealVNC 5.3",              "RFB 003.008",                              SVC_BANNER, B_VNC,   sizeof(B_VNC) - 1},
  // Redis stays silent until spoken to, exactly like the real server.
  { 6379, "Redis",   "Redis 6.0.16",             "-DENIED protected mode",                   SVC_REDIS,  nullptr, 0},
  { 8080, "HTTP-alt","Apache 2.4.52 (Ubuntu)",   "HTTP/1.1 200 — Apache/2.4.52 (Ubuntu)",    SVC_HTTP,   nullptr, 0},
};
static const size_t CATALOGUE_N = sizeof(CATALOGUE) / sizeof(CATALOGUE[0]);

const ServiceDef* svcCatalogue(size_t& count) { count = CATALOGUE_N; return CATALOGUE; }

const ServiceDef* svcFind(uint16_t port) {
  for (const ServiceDef& d : CATALOGUE) if (d.port == port) return &d;
  return nullptr;
}

// ------------------------------------------------------------- listeners ---

struct Listener {
  WiFiServer*       srv;
  const ServiceDef* def;
};
static Listener s_listeners[HP_MAX_PORTS];
static uint8_t  s_listenerCount = 0;
static uint32_t s_catVersion = 1;

// Requests a re-arm. Callable from any task: the work itself must happen on the
// task that pumps the listeners, because svcPump() is dereferencing these very
// pointers on the other core and deleting them underneath it is a
// use-after-free. The flag is picked up at the top of the next pump.
static volatile bool s_reapply = false;
void svcApplyConfig() { s_reapply = true; }

// ----------------------------------------------------------- connections ---

static const uint8_t  MAX_CONNS       = 6;       // see the socket budget in hp_common.h
// One internet-facing scanner will happily open every slot and sit on them.
// Reserving headroom means a second visitor is still served while the first is
// being greedy — the honeypot stays useful during a flood instead of going deaf.
static const uint8_t  MAX_CONNS_PER_IP = 4;
static const uint32_t IDLE_BANNER_MS  = 4000;    // binary ports: say hi, listen, go
static const uint32_t IDLE_LINE_MS    = 25000;   // FTP/SMTP/POP3/IMAP hold a session
static const uint32_t IDLE_SHELL_MS   = 180000;  // humans think slowly
static const uint32_t MAX_SESSION_MS  = 900000;  // nothing legitimate runs 15 min
static const uint16_t MAX_LINE        = 512;
static const uint16_t MAX_RX_BYTES    = 8192;    // hard cap per session

enum ConnState : uint8_t { C_FREE = 0, C_LIVE, C_LINGER };

struct Conn {
  WiFiClient        cli;
  const ServiceDef* def;
  uint8_t           state;
  uint32_t          ip;
  uint32_t          openedAt;
  uint32_t          lastRx;
  uint32_t          rxBytes;
  String            line;
  ShellSession      sh;
  uint8_t           iac;       // telnet IAC parser state
  bool              quiet;     // throttled: serve normally, skip noise events
};
static Conn s_conns[MAX_CONNS];

// -------------------------------------------------------- rate limiting ---

// A scanner opens hundreds of connections a second, and writing an event to
// flash for each one would wear the chip and bury the interesting entries.
//
// The throttle deliberately does NOT refuse the connection. Refusing is what
// gives the game away: a host that answers the first forty probes and then
// stops is obviously not a file server. Serving a banner is nearly free, so we
// always serve it and throttle only the logging, recording one summary line per
// window instead.
struct RateBin { uint32_t ip; uint32_t windowStart; uint16_t count; bool noted; };
static const uint8_t  RATE_BINS   = 16;
static const uint16_t RATE_MAX    = 60;      // events logged ...
static const uint32_t RATE_WINDOW = 10000;   // ... per 10 s from one host
static RateBin s_rate[RATE_BINS];
static uint32_t s_throttled = 0;
static uint32_t s_nonLocal  = 0;

// True when this connection should produce log events.
static bool rateLogAllowed(uint32_t ip) {
  uint32_t now = millis();
  uint8_t  freeSlot = RATE_BINS;
  for (uint8_t i = 0; i < RATE_BINS; i++) {
    if (s_rate[i].ip == ip) {
      if (now - s_rate[i].windowStart > RATE_WINDOW) {
        s_rate[i].windowStart = now;
        s_rate[i].count = 0;
        s_rate[i].noted = false;
      }
      if (++s_rate[i].count > RATE_MAX) {
        s_throttled++;
        if (!s_rate[i].noted) {
          s_rate[i].noted = true;
          evLog(EV_CONNECT, SEV_ALERT, ip, 0,
                "sustained scan: over %u connections in %us, further hits summarised",
                RATE_MAX, (unsigned)(RATE_WINDOW / 1000));
        }
        return false;
      }
      return true;
    }
    if (!s_rate[i].ip && freeSlot == RATE_BINS) freeSlot = i;
  }
  uint8_t slot = (freeSlot < RATE_BINS) ? freeSlot : (ip % RATE_BINS);
  s_rate[slot] = {ip, now, 1, false};
  return true;
}

// ------------------------------------------------------------ responders ---

static void sendHttp(Conn& c) {
  static const char* PAGE =
    "<!DOCTYPE html><html><head><title>Index of /</title></head><body>"
    "<h1>Index of /</h1><hr><pre><a href=\"../\">../</a>\n"
    "<a href=\"backup/\">backup/</a>                     12-Feb-2024 08:41    -\n"
    "<a href=\"phpmyadmin/\">phpmyadmin/</a>                 04-Jan-2024 19:02    -\n"
    "</pre><hr><address>Apache/2.4.52 (Ubuntu) Server at 10.20.4.11 Port 80</address>"
    "</body></html>";
  size_t len = strlen(PAGE);
  c.cli.printf("HTTP/1.1 200 OK\r\n"
               "Date: Mon, 12 Feb 2024 08:41:29 GMT\r\n"
               "Server: Apache/2.4.52 (Ubuntu)\r\n"
               "Content-Type: text/html;charset=UTF-8\r\n"
               "Content-Length: %u\r\n"
               "Connection: close\r\n\r\n%s", (unsigned)len, PAGE);
}

// Answers a version.bind CHAOS TXT query, echoing the query id so resolvers and
// nmap's dns-nsid script accept it.
static void sendDns(Conn& c, const uint8_t* query, size_t qlen) {
  uint16_t id = 0;
  if (qlen >= 4) id = (query[2] << 8) | query[3];   // +2 skips the TCP length prefix

  uint8_t resp[] = {
    0x00, 0x00,                                       // TCP length, patched below
    0x00, 0x00, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x07, 'v','e','r','s','i','o','n', 0x04, 'b','i','n','d', 0x00,
    0x00, 0x10, 0x00, 0x03,
    0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
    0x07, '9','.','1','8','.','1','8'
  };
  uint16_t dnsLen = sizeof(resp) - 2;
  resp[0] = dnsLen >> 8; resp[1] = dnsLen & 0xFF;
  resp[2] = id >> 8;     resp[3] = id & 0xFF;
  c.cli.write(resp, sizeof(resp));
}

// Renders raw probe bytes as a printable one-liner for the event detail.
static String describeProbe(const uint8_t* buf, size_t n) {
  String s;
  s.reserve(n + 8);
  for (size_t i = 0; i < n && s.length() < 120; i++) {
    uint8_t b = buf[i];
    if (b >= 0x20 && b < 0x7F) s += (char)b;
    else if (b == '\r' || b == '\n') s += ' ';
    else { char t[5]; snprintf(t, sizeof(t), "\\x%02X", b); s += t; }
  }
  s.trim();
  return s.length() ? s : String("(silent)");
}

// ------------------------------------------------------------- telnet io ---

// Strips IAC negotiation so option bytes never end up inside a captured
// username. v1 logged them verbatim, which corrupted every credential.
// Returns true if the byte is ordinary data.
static bool telnetFilter(Conn& c, uint8_t b) {
  switch (c.iac) {
    case 0: if (b == 0xFF) { c.iac = 1; return false; } return true;
    case 1:
      if (b == 0xFF) { c.iac = 0; return true; }          // escaped 0xFF
      if (b >= 0xFB && b <= 0xFE) { c.iac = 2; return false; }  // WILL/WONT/DO/DONT
      if (b == 0xFA) { c.iac = 3; return false; }               // subnegotiation
      c.iac = 0; return false;
    case 2: c.iac = 0; return false;                       // option byte
    case 3: if (b == 0xF0) c.iac = 0; return false;        // until SE
  }
  return true;
}

static void telnetHello(Conn& c) {
  // WILL ECHO, WILL SUPPRESS-GO-AHEAD, DO SUPPRESS-GO-AHEAD. Claiming ECHO is
  // what makes a real telnetd responsible for echoing typed characters — so we
  // must actually do it below, or the session feels dead to a human.
  static const uint8_t NEG[] = {0xFF, 0xFB, 0x01, 0xFF, 0xFB, 0x03, 0xFF, 0xFD, 0x03};
  c.cli.write(NEG, sizeof(NEG));
  c.cli.print("\r\nUbuntu 22.04.3 LTS\r\n");
  c.cli.printf("%s login: ", g_cfg.hostname);
}

// ------------------------------------------------------- line protocols ---

static void closeConn(Conn& c, const char* why);   // defined with the accept path

static bool isLineProto(uint8_t k) {
  return k == SVC_FTP || k == SVC_SMTP || k == SVC_POP3 || k == SVC_IMAP || k == SVC_REDIS;
}

// Records a username/password pair offered to a non-telnet service. These are
// as valuable as the telnet ones and v1 captured none of them.
static void logCred(Conn& c, const char* proto, const char* user, const String& pass) {
  evLog(EV_LOGIN, SEV_ALERT, c.ip, c.def->port, "%s %s : %s", proto,
        user && user[0] ? user : "?",
        pass.length() ? hpSanitize(pass, 40).c_str() : "<empty>");
}

// Answers one command line. Returns false once the peer has said goodbye.
static bool respondText(Conn& c, const String& line) {
  String up = line;
  up.toUpperCase();
  // Everything after the verb, trimmed.
  auto tail = [&](uint8_t n) { String a = line.substring(n); a.trim(); return a; };

  switch (c.def->kind) {
    case SVC_FTP:
      if (up.startsWith("USER")) {
        hpCopy(c.sh.pendingUser, sizeof(c.sh.pendingUser), hpSanitize(tail(4), 30).c_str());
        c.cli.printf("331 Password required for %s\r\n", c.sh.pendingUser);
      } else if (up.startsWith("PASS")) {
        logCred(c, "ftp", c.sh.pendingUser, tail(4));
        c.cli.print("530 Login incorrect.\r\n");
      } else if (up.startsWith("SYST")) c.cli.print("215 UNIX Type: L8\r\n");
      else if (up.startsWith("FEAT")) c.cli.print("211-Features:\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n UTF8\r\n211 End\r\n");
      else if (up.startsWith("PWD"))  c.cli.print("257 \"/\" is the current directory\r\n");
      else if (up.startsWith("TYPE")) c.cli.print("200 Type set to I\r\n");
      else if (up.startsWith("QUIT")) { c.cli.print("221 Goodbye.\r\n"); return false; }
      else c.cli.print("530 Please login with USER and PASS.\r\n");
      return true;

    case SVC_SMTP: {
      char ip[16];
      hpFormatIp(c.ip, ip, sizeof(ip));
      if (up.startsWith("EHLO")) {
        c.cli.printf("250-mail.corp.local Hello [%s]\r\n250-SIZE 52428800\r\n"
                     "250-8BITMIME\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n", ip);
      }
      else if (up.startsWith("HELO")) c.cli.print("250 mail.corp.local\r\n");
      else if (up.startsWith("AUTH")) c.cli.print("334 VXNlcm5hbWU6\r\n");   // "Username:"
      else if (up.startsWith("MAIL")) c.cli.print("250 2.1.0 Ok\r\n");
      else if (up.startsWith("RCPT")) c.cli.print("454 4.7.1 Relay access denied\r\n");
      else if (up.startsWith("DATA")) c.cli.print("354 End data with <CR><LF>.<CR><LF>\r\n");
      else if (up.startsWith("RSET")) c.cli.print("250 2.0.0 Ok\r\n");
      else if (up.startsWith("VRFY")) c.cli.print("252 2.0.0 Cannot VRFY user\r\n");
      else if (up.startsWith("NOOP")) c.cli.print("250 2.0.0 Ok\r\n");
      else if (up.startsWith("QUIT")) { c.cli.print("221 2.0.0 Bye\r\n"); return false; }
      else c.cli.print("502 5.5.2 Error: command not recognized\r\n");
      return true;
    }

    case SVC_POP3:
      if (up.startsWith("USER")) {
        hpCopy(c.sh.pendingUser, sizeof(c.sh.pendingUser), hpSanitize(tail(4), 30).c_str());
        c.cli.print("+OK\r\n");
      } else if (up.startsWith("PASS")) {
        logCred(c, "pop3", c.sh.pendingUser, tail(4));
        c.cli.print("-ERR [AUTH] Authentication failed.\r\n");
      }
      else if (up.startsWith("CAPA")) c.cli.print("+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nUSER\r\nSASL PLAIN LOGIN\r\n.\r\n");
      else if (up.startsWith("QUIT")) { c.cli.print("+OK Logging out.\r\n"); return false; }
      else c.cli.print("-ERR Unknown command.\r\n");
      return true;

    case SVC_IMAP: {
      // Every IMAP reply must echo the client's tag or the client hangs.
      int sp = line.indexOf(' ');
      String tag  = sp > 0 ? line.substring(0, sp) : String("*");
      String rest = sp > 0 ? line.substring(sp + 1) : String();
      String ru = rest;
      ru.toUpperCase();

      if (ru.startsWith("CAPABILITY")) {
        c.cli.print("* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN\r\n");
        c.cli.printf("%s OK Capability completed.\r\n", tag.c_str());
      } else if (ru.startsWith("LOGIN")) {
        String args = rest.substring(5);
        args.trim();
        args.replace("\"", "");
        int gap = args.indexOf(' ');
        String u = gap > 0 ? args.substring(0, gap) : args;
        String p = gap > 0 ? args.substring(gap + 1) : String();
        hpCopy(c.sh.pendingUser, sizeof(c.sh.pendingUser), hpSanitize(u, 30).c_str());
        logCred(c, "imap", c.sh.pendingUser, p);
        c.cli.printf("%s NO [AUTHENTICATIONFAILED] Authentication failed.\r\n", tag.c_str());
      } else if (ru.startsWith("LOGOUT")) {
        c.cli.print("* BYE Logging out\r\n");
        c.cli.printf("%s OK Logout completed.\r\n", tag.c_str());
        return false;
      } else if (ru.startsWith("ID")) {
        c.cli.print("* ID (\"name\" \"Dovecot\")\r\n");
        c.cli.printf("%s OK ID completed.\r\n", tag.c_str());
      } else if (ru.startsWith("NOOP")) {
        c.cli.printf("%s OK NOOP completed.\r\n", tag.c_str());
      } else {
        c.cli.printf("%s BAD Error in IMAP command received by server.\r\n", tag.c_str());
      }
      return true;
    }

    case SVC_REDIS:
      // RESP framing lines carry no command; stay quiet so the reply sequence
      // still lines up with what a real server would send.
      if (line.startsWith("*") || line.startsWith("$")) return true;
      if (up.startsWith("PING")) c.cli.print("+PONG\r\n");
      else if (up.startsWith("AUTH")) { logCred(c, "redis", "default", tail(4));
                                        c.cli.print("-ERR invalid password\r\n"); }
      else if (up.startsWith("QUIT")) { c.cli.print("+OK\r\n"); return false; }
      else c.cli.print("-DENIED Redis is running in protected mode because protected "
                       "mode is enabled and no password is set.\r\n");
      return true;

    default:
      return true;
  }
}

static void pumpText(Conn& c) {
  while (c.cli.available()) {
    char ch = c.cli.read();
    if (++c.rxBytes > MAX_RX_BYTES) { closeConn(c, "input limit"); return; }
    c.lastRx = millis();

    if (ch == '\n') {
      String line = c.line;
      c.line = String();
      line.trim();
      if (!line.length()) continue;
      if (!c.quiet) evLog(EV_PROBE, SEV_NOTICE, c.ip, c.def->port, "%s", hpSanitize(line, 120).c_str());
      if (!respondText(c, line)) { closeConn(c, "peer quit"); return; }
      continue;
    }
    if (ch == '\r') continue;
    if (c.line.length() < MAX_LINE) c.line += ch;
  }
}

// ---------------------------------------------------------------- accept ---

static Conn* freeSlot() {
  for (Conn& c : s_conns) if (c.state == C_FREE) return &c;
  return nullptr;
}

static void closeConn(Conn& c, const char* why) {
  if (c.state != C_FREE && !c.quiet) {
    evLog(EV_DISCONNECT, SEV_INFO, c.ip, c.def ? c.def->port : 0,
          "session closed after %lus (%s)",
          (unsigned long)((millis() - c.openedAt) / 1000), why);
  }
  c.cli.stop();
  c.state = C_FREE;
  c.line = String();
  c.def = nullptr;
  c.rxBytes = 0;
  c.iac = 0;
}

static void acceptOn(Listener& L) {
  if (!L.srv->hasClient()) return;
  WiFiClient cli = L.srv->accept();
  if (!cli) return;

  uint32_t ip = (uint32_t)cli.remoteIP();

  // LAN-only: hang up on anything from outside the local network without
  // answering. A device meant as an internal canary should not be advertising
  // fake services to the internet even if a port forward is left in place.
  if (g_cfg.lanOnly && !hpIsPrivateV4(ip)) {
    if ((s_nonLocal++ & 0x1F) == 0) {
      evLog(EV_CONNECT, SEV_NOTICE, ip, L.def->port,
            "ignored: LAN-only mode is on and this is not a local address");
    }
    cli.stop();
    return;
  }

  bool quiet = !rateLogAllowed(ip);

  uint8_t fromSameHost = 0;
  for (Conn& x : s_conns) if (x.state != C_FREE && x.ip == ip) fromSameHost++;
  if (fromSameHost >= MAX_CONNS_PER_IP) {
    if (!quiet) evLog(EV_CONNECT, SEV_NOTICE, ip, L.def->port,
                      "declined, %u slots already held by this host", fromSameHost);
    cli.stop();
    return;
  }

  Conn* c = freeSlot();
  if (!c) {
    // Pool exhausted. Drop rather than queue: an attacker holding sockets open
    // must not be able to delay the ports that still have capacity.
    if (!quiet) evLog(EV_CONNECT, SEV_NOTICE, ip, L.def->port,
                      "refused, all %u slots busy", MAX_CONNS);
    cli.stop();
    return;
  }

  c->cli      = cli;
  c->def      = L.def;
  c->state    = C_LIVE;
  c->ip       = ip;
  c->openedAt = millis();
  c->lastRx   = c->openedAt;
  c->rxBytes  = 0;
  c->iac      = 0;
  c->quiet    = quiet;
  c->line     = String();
  c->cli.setNoDelay(true);

  if (!quiet) evLog(EV_CONNECT, SEV_INFO, ip, L.def->port,
                    "%s connection opened", L.def->name);

  if (L.def->kind == SVC_TELNET) {
    shellReset(c->sh);
    telnetHello(*c);
  } else {
    memset(&c->sh, 0, sizeof(c->sh));
    // Anything with a greeting speaks first; HTTP, DNS and Redis wait to be
    // asked, exactly as the real services do.
    if (L.def->banner) c->cli.write(L.def->banner, L.def->bannerLen);
  }
}

// ------------------------------------------------------------------ pump ---

static void pumpTelnet(Conn& c) {
  while (c.cli.available()) {
    uint8_t b = c.cli.read();
    if (++c.rxBytes > MAX_RX_BYTES) { closeConn(c, "input limit"); return; }
    c.lastRx = millis();
    if (!telnetFilter(c, b)) continue;

    if (b == '\n' || b == '\r') {
      if (b == '\r' && c.cli.peek() == '\n') c.cli.read();   // swallow CRLF pair
      c.cli.print("\r\n");
      String line = c.line;
      c.line = String();
      if (!shellFeedLine(c.sh, line, c.cli, c.ip)) { closeConn(c, "logout"); return; }
      continue;
    }
    if (b == 0x7F || b == 0x08) {                            // backspace
      if (c.line.length()) { c.line.remove(c.line.length() - 1); c.cli.print("\b \b"); }
      continue;
    }
    if (b == 0x03) { c.cli.print("^C\r\n"); c.line = String();
                     c.cli.print(shellPrompt(c.sh)); continue; }
    if (b < 0x20) continue;

    if (c.line.length() < MAX_LINE) {
      c.line += (char)b;
      // We negotiated WILL ECHO, so we owe the client an echo — except while
      // they're typing a password, which a real telnetd also suppresses.
      if (c.sh.stage != SH_PASSWORD && c.sh.stage != SH_SUDO) c.cli.write(b);
    }
  }
}

static void pumpProbe(Conn& c) {
  uint8_t buf[256];
  size_t n = 0;
  while (c.cli.available() && n < sizeof(buf)) buf[n++] = c.cli.read();
  if (!n) return;

  c.rxBytes += n;
  c.lastRx = millis();

  switch (c.def->kind) {
    case SVC_DNS:
      sendDns(c, buf, n);
      if (!c.quiet) evLog(EV_PROBE, SEV_NOTICE, c.ip, c.def->port, "DNS query, %u bytes", (unsigned)n);
      c.state = C_LINGER;
      break;

    case SVC_HTTP: {
      String req = describeProbe(buf, n);
      // Path traversal and shell-injection attempts in a URL are worth flagging.
      bool nasty = req.indexOf("..") >= 0 || req.indexOf("${") >= 0 ||
                   req.indexOf("/bin/") >= 0 || req.indexOf("cgi-bin") >= 0;
      if (!c.quiet || nasty) evLog(EV_PROBE, nasty ? SEV_ALERT : SEV_NOTICE, c.ip, c.def->port,
                                   "%s", req.substring(0, 140).c_str());
      sendHttp(c);
      c.state = C_LINGER;
      break;
    }

    default:
      if (!c.quiet) evLog(EV_PROBE, SEV_NOTICE, c.ip, c.def->port, "%s", describeProbe(buf, n).c_str());
      if (c.def->kind == SVC_BANNER) c.state = C_LINGER;
      break;
  }
}

static void applyConfigNow() {
  for (uint8_t i = 0; i < s_listenerCount; i++) {
    if (s_listeners[i].srv) { s_listeners[i].srv->end(); delete s_listeners[i].srv; }
  }
  s_listenerCount = 0;

  for (uint8_t i = 0; i < g_cfg.portCount && s_listenerCount < HP_MAX_PORTS; i++) {
    const ServiceDef* def = svcFind(g_cfg.ports[i]);
    if (!def) continue;                     // unknown port, nothing to imitate
    WiFiServer* srv = new WiFiServer(def->port, 4);
    srv->begin();
    srv->setNoDelay(true);
    s_listeners[s_listenerCount++] = {srv, def};
    Serial.printf("[svc] armed :%-5u %s\n", def->port, def->product);
  }

  s_catVersion++;

  // Disarming a port should take effect now, not whenever its sessions happen
  // to time out.
  for (Conn& c : s_conns) {
    if (c.state == C_FREE || !c.def) continue;
    bool stillArmed = false;
    for (uint8_t i = 0; i < s_listenerCount; i++) {
      if (s_listeners[i].def->port == c.def->port) { stillArmed = true; break; }
    }
    if (!stillArmed) closeConn(c, "port disarmed");
  }
}

void svcPump() {
  if (s_reapply) { s_reapply = false; applyConfigNow(); }

  for (uint8_t i = 0; i < s_listenerCount; i++) acceptOn(s_listeners[i]);

  for (Conn& c : s_conns) {
    if (c.state == C_FREE) continue;

    if (!c.cli.connected() && !c.cli.available()) { closeConn(c, "peer closed"); continue; }

    if (c.state == C_LIVE) {
      if (c.def->kind == SVC_TELNET)      pumpTelnet(c);
      else if (isLineProto(c.def->kind))  pumpText(c);
      else                                pumpProbe(c);
      if (c.state == C_FREE) continue;
    }

    uint32_t idleCap;
    if (c.def->kind == SVC_TELNET)        idleCap = IDLE_SHELL_MS;
    // Line protocols must stay open between commands or a scanner records them
    // as "tcpwrapped" instead of identifying the service.
    else if (isLineProto(c.def->kind))    idleCap = IDLE_LINE_MS;
    // SSH gets a grace period so nmap's ssh2-enum-algos probe can complete.
    else if (c.def->kind == SVC_SSH)      idleCap = 8000;
    else                                  idleCap = IDLE_BANNER_MS;
    if (c.state == C_LINGER) idleCap = 300;

    // Sample the clock *after* pumping. Reading it before means a connection
    // that just sent data has lastRx ahead of now, the unsigned subtraction
    // wraps to ~4.29e9, and the session is killed the instant it says anything.
    // Signed deltas keep it correct across the millis() rollover too.
    uint32_t now = millis();
    if ((int32_t)(now - c.lastRx)   > (int32_t)idleCap)        { closeConn(c, "idle"); continue; }
    if ((int32_t)(now - c.openedAt) > (int32_t)MAX_SESSION_MS) { closeConn(c, "session limit"); continue; }
  }
}

uint8_t svcActiveConnections() {
  uint8_t n = 0;
  for (Conn& c : s_conns) if (c.state != C_FREE) n++;
  return n;
}

uint32_t svcCatalogueVersion() { return s_catVersion; }

void svcStatusJson(JsonObject out, uint32_t knownVersion) {
  out["catVersion"] = s_catVersion;
  out["slots"]     = MAX_CONNS;
  out["active"]    = svcActiveConnections();
  out["throttled"] = s_throttled;
  out["lanOnly"]   = g_cfg.lanOnly;
  out["nonLocal"]  = s_nonLocal;

  if (knownVersion == s_catVersion) return;   // client's copy is current

  JsonArray arr = out["catalogue"].to<JsonArray>();
  for (const ServiceDef& d : CATALOGUE) {
    JsonObject o = arr.add<JsonObject>();
    o["port"]    = d.port;
    o["name"]    = d.name;
    o["product"] = d.product;
    o["preview"] = d.preview;
    o["armed"]   = cfgPortArmed(d.port);
    o["shell"]   = d.kind == SVC_TELNET;
  }
}
