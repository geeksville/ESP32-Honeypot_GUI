// Fake Linux shell.
//
// Two design rules drive everything here:
//   1. The fake filesystem is a table, not a chain of if-statements. Adding
//      bait is a one-line change and `ls`/`cat`/`cd` stay consistent with it.
//   2. Realism is measured against what actually connects to port 23, which is
//      overwhelmingly Mirai-family loaders, not humans. Their probe sequence is
//      answered byte-accurately so they proceed to the payload stage, which is
//      the part worth capturing.
#include "hp_shell.h"
#include "hp_config.h"
#include "hp_events.h"
#include "hp_artifacts.h"
#include <Print.h>

// ------------------------------------------------------------------- vfs ---

struct VNode {
  const char* path;
  bool        dir;
  const char* mode;
  uint16_t    size;
  const char* body;   // nullptr for directories
};

// Bait chosen to look like a small business file server: credentials worth
// stealing, a backup script with a hardcoded password, an SSH key.
static const char* PASSWD_BODY =
  "root:x:0:0:root:/root:/bin/bash\n"
  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
  "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
  "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
  "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
  "mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false\n"
  "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n";

static const char* SHADOW_BODY =
  "root:$6$Xk2p9vQd$JqM3nR7wYtLb5cVzHfPd8uKsA1eNgOiTrWxYzB4mCvDfEhGjIkLmNoPqRsTuVwXyZ0:19722:0:99999:7:::\n"
  "daemon:*:19722:0:99999:7:::\n"
  "mysql:!:19722:0:99999:7:::\n";

static const char* BACKUP_SH_BODY =
  "#!/bin/bash\n"
  "# nightly offsite sync - runs from cron at 03:15\n"
  "MYSQL_USER=svc_backup\n"
  "MYSQL_PASS='Wint3r2024!Backup'\n"
  "REMOTE=backup@10.20.4.19\n"
  "mysqldump -u\"$MYSQL_USER\" -p\"$MYSQL_PASS\" --all-databases > /var/backups/db.sql\n"
  "rsync -az /var/backups/ \"$REMOTE\":/vol/backups/\n";

static const char* CREDS_BODY =
  "# migrated from the old NAS, delete once verified\n"
  "vsphere.local\tadministrator@vsphere.local\tvC3nt3r!Adm1n\n"
  "nas01\tadmin\tNas-2019-Storage\n"
  "billing-db\tsvc_billing\tb1ll1ng$vc2023\n";

static const char* ID_RSA_BODY =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
  "NhAAAAAwEAAQAAAYEAvT9mK4pQeR2xHnJdLbW8sYcVfGtNzXmAqPoRuIeKjHgFdSaCvBnM\n"
  "...\n"
  "-----END OPENSSH PRIVATE KEY-----\n";

static const VNode VFS[] = {
  {"/",                            true,  "drwxr-xr-x", 4096, nullptr},
  {"/etc",                         true,  "drwxr-xr-x", 4096, nullptr},
  {"/etc/passwd",                  false, "-rw-r--r--",  412, PASSWD_BODY},
  {"/etc/shadow",                  false, "-rw-r-----",  198, SHADOW_BODY},
  {"/etc/hostname",                false, "-rw-r--r--",   14, nullptr},   // filled at runtime
  {"/etc/issue",                   false, "-rw-r--r--",   27, "Ubuntu 22.04.3 LTS \\n \\l\n"},
  {"/root",                        true,  "drwx------", 4096, nullptr},
  {"/home",                        true,  "drwxr-xr-x", 4096, nullptr},
  {"/var",                         true,  "drwxr-xr-x", 4096, nullptr},
  {"/var/backups",                 true,  "drwxr-xr-x", 4096, nullptr},
  {"/var/backups/db.sql",          false, "-rw-r-----", 48211, "-- MySQL dump 10.13  Distrib 8.0.35\n-- Host: localhost    Database: billing\n"},
  {"/opt",                         true,  "drwxr-xr-x", 4096, nullptr},
  {"/opt/backup.sh",               false, "-rwxr-xr-x",  394, BACKUP_SH_BODY},
  {"/tmp",                         true,  "drwxrwxrwt", 4096, nullptr},
  {"/proc",                        true,  "dr-xr-xr-x",    0, nullptr},
  {"/proc/version",                false, "-r--r--r--",  142, "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc 11.4.0) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n"},
  {"/proc/cpuinfo",                false, "-r--r--r--", 2048, "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz\ncpu MHz\t\t: 2194.842\ncache size\t: 30720 KB\n"},
  {"/proc/mounts",                 false, "-r--r--r--",  512, "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,noexec 0 0\n"},
};

// Home-relative nodes are built from the configured user at first use, so the
// tree always agrees with whatever name the operator picked.
struct HomeNode { const char* rel; bool dir; const char* mode; uint16_t size; const char* body; };
static const HomeNode HOME_VFS[] = {
  {"",                    true,  "drwxr-xr-x", 4096, nullptr},
  {"/.ssh",               true,  "drwx------", 4096, nullptr},
  {"/.ssh/id_rsa",        false, "-rw-------", 2602, ID_RSA_BODY},
  {"/.ssh/known_hosts",   false, "-rw-r--r--",  444, "10.20.4.19 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1kQ4pXvY7mNc2Rt\n"},
  {"/.bash_history",      false, "-rw-------",  318, "ssh backup@10.20.4.19\nmysql -u root -p\nsudo systemctl restart nginx\nscp /var/backups/db.sql backup@10.20.4.19:/vol/\nhistory -c\n"},
  {"/credentials.txt",    false, "-rw-r--r--",  221, CREDS_BODY},
  {"/notes.md",           false, "-rw-r--r--",   96, "# handover\n- vpn cert expires in march\n- billing db still on the old scheme\n"},
};

static String homeDir() { return String("/home/") + g_cfg.shellUser; }

// Resolves a node by absolute path. Returns nullptr if it doesn't exist.
// `outBody` may be rewritten for nodes whose content depends on config.
static const VNode* vfsFind(const String& abs, String& outBody) {
  String home = homeDir();
  if (abs == "/etc/hostname") { outBody = String(g_cfg.hostname) + "\n"; }

  for (const VNode& n : VFS) {
    if (abs == n.path) {
      if (n.body) outBody = n.body;
      return &n;
    }
  }
  for (const HomeNode& h : HOME_VFS) {
    if (abs == home + h.rel) {
      static VNode tmp;
      tmp = {"", h.dir, h.mode, h.size, h.body};
      if (h.body) outBody = h.body;
      return &tmp;
    }
  }
  return nullptr;
}

// Collapses ".", ".." and duplicate slashes. `base` must be absolute.
static String vfsResolve(const String& base, String rel) {
  String home = homeDir();
  if (rel == "~" || rel.startsWith("~/")) rel = home + rel.substring(1);
  if (rel.length() == 0) rel = home;

  String path = rel.startsWith("/") ? rel : (base + "/" + rel);

  String out;
  int i = 0;
  while (i < (int)path.length()) {
    while (i < (int)path.length() && path[i] == '/') i++;
    int j = i;
    while (j < (int)path.length() && path[j] != '/') j++;
    String seg = path.substring(i, j);
    i = j;
    if (seg == "" || seg == ".") continue;
    if (seg == "..") {
      int slash = out.lastIndexOf('/');
      if (slash >= 0) out = out.substring(0, slash);
      continue;
    }
    out += "/" + seg;
  }
  return out.length() ? out : "/";
}

// Lists direct children of `dir` into the callback.
template <typename F>
static void vfsChildren(const String& dir, F cb) {
  String home = homeDir();
  String prefix = (dir == "/") ? "/" : dir + "/";

  auto emit = [&](const String& full, const VNode& n) {
    if (!full.startsWith(prefix) || full == dir) return;
    String rest = full.substring(prefix.length());
    if (rest.length() == 0 || rest.indexOf('/') >= 0) return;   // not a direct child
    cb(rest, n);
  };

  for (const VNode& n : VFS) emit(String(n.path), n);
  for (const HomeNode& h : HOME_VFS) {
    VNode tmp = {"", h.dir, h.mode, h.size, h.body};
    emit(home + h.rel, tmp);
  }
  // /home contains the user's directory even though HOME_VFS[0].rel is "".
  if (dir == "/home") { /* handled by emit above via home + "" */ }
}

// --------------------------------------------------------------- session ---

void shellReset(ShellSession& s) {
  memset(&s, 0, sizeof(s));
  s.stage = SH_LOGIN;
  hpCopy(s.cwd, sizeof(s.cwd), homeDir().c_str());
}

String shellPrompt(const ShellSession& s) {
  String home = homeDir();
  String disp = s.cwd;
  if (disp == home) disp = "~";
  else if (disp.startsWith(home + "/")) disp = "~" + disp.substring(home.length());
  bool root = strcmp(s.user, "root") == 0;
  return String(s.user) + "@" + g_cfg.hostname + ":" + disp + (root ? "# " : "$ ");
}

void shellGreet(ShellSession& s, Print& out) {
  out.print("\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n");
  out.print(" * Documentation:  https://help.ubuntu.com\r\n");
  out.print(" * Management:     https://landscape.canonical.com\r\n");
  out.print(" * Support:        https://ubuntu.com/advantage\r\n\r\n");
  out.printf("Last login: Mon Feb 12 08:41:07 2024 from 10.20.4.8\r\n");
  s.greeted = true;
}

// ---------------------------------------------------------- botnet probes ---

// Mirai and its forks fingerprint busybox before dropping a payload. Answering
// with busybox's real "applet not found" text keeps them talking; a generic
// "command not found" makes them hang up before revealing the loader URL.
static bool handleBusybox(const String& cmd, Print& out, uint32_t ip) {
  int idx = cmd.indexOf("busybox");
  if (idx < 0) return false;
  String arg = cmd.substring(idx + 7);
  arg.trim();
  int sp = arg.indexOf(' ');
  if (sp > 0) arg = arg.substring(0, sp);
  if (arg.length() == 0) arg = "BUSYBOX";
  evLog(EV_COMMAND, SEV_ALERT, ip, 23, "botnet fingerprint: busybox %s", arg.c_str());
  out.printf("%s: applet not found\r\n", arg.c_str());
  return true;
}

// The loader's control words. Real busybox shells accept them silently.
static bool handleLoaderVerb(const String& cmd, Print& out) {
  if (cmd == "enable" || cmd == "system" || cmd == "shell" || cmd == "sh") {
    out.print("\r\n");
    return true;
  }
  return false;
}

// Pulls the first URL-ish token out of a download command.
static String extractUrl(const String& cmd) {
  int at = -1;
  const char* marks[] = {"http://", "https://", "ftp://", "tftp://"};
  for (const char* m : marks) { int i = cmd.indexOf(m); if (i >= 0 && (at < 0 || i < at)) at = i; }
  if (at < 0) {
    // tftp -g -r file -l file HOST  → treat the trailing token as the source.
    int sp = cmd.lastIndexOf(' ');
    return sp >= 0 ? cmd.substring(sp + 1) : String();
  }
  int end = cmd.indexOf(' ', at);
  return end < 0 ? cmd.substring(at) : cmd.substring(at, end);
}

// ---------------------------------------------------------------- ls/cat ---

static void doLs(const ShellSession& s, const String& arg, Print& out) {
  // Flags must be read per character, not as substrings: "-la" contains
  // neither "-l" nor "-a" as a substring, and bundling flags is the normal
  // way people type this.
  bool longList = false, showAll = false;
  String target;

  int i = 0;
  while (i < (int)arg.length()) {
    while (i < (int)arg.length() && arg[i] == ' ') i++;
    int j = arg.indexOf(' ', i);
    if (j < 0) j = arg.length();
    String tok = arg.substring(i, j);
    if (tok.startsWith("-")) {
      for (uint16_t k = 1; k < tok.length(); k++) {
        if (tok[k] == 'l') longList = true;
        if (tok[k] == 'a' || tok[k] == 'A') showAll = true;
      }
    } else if (tok.length() && !target.length()) {
      target = tok;
    }
    i = j;
  }
  String dir = vfsResolve(s.cwd, target);

  String body;
  const VNode* n = vfsFind(dir, body);
  if (!n) { out.printf("ls: cannot access '%s': No such file or directory\r\n", dir.c_str()); return; }
  if (!n->dir) { out.printf("%s\r\n", dir.c_str()); return; }

  String plain;
  uint16_t blocks = 0;
  String rows;
  vfsChildren(dir, [&](const String& name, const VNode& child) {
    if (!showAll && name.startsWith(".")) return;
    blocks += (child.size + 1023) / 1024;
    if (longList) {
      char line[160];
      // Precision on the owner fields: the configured user may be far longer
      // than the column, and without it a long name truncates the whole row.
      snprintf(line, sizeof(line), "%s %2d %-8.16s %-8.16s %8u Feb 12 08:41 %.64s\r\n",
               child.mode, child.dir ? 2 : 1,
               child.dir && strcmp(child.mode, "drwx------") ? "root" : g_cfg.shellUser,
               child.dir && strcmp(child.mode, "drwx------") ? "root" : g_cfg.shellUser,
               child.size, name.c_str());
      rows += line;
    } else {
      if (plain.length()) plain += "  ";
      plain += name;
    }
  });

  if (longList) { out.printf("total %u\r\n", blocks ? blocks : 4); out.print(rows); }
  else if (plain.length()) out.print(plain + "\r\n");
}

static void doCat(const ShellSession& s, const String& arg, Print& out, uint32_t ip) {
  if (!arg.length()) return;
  String abs = vfsResolve(s.cwd, arg);
  String body;
  const VNode* n = vfsFind(abs, body);
  if (!n)        { out.printf("cat: %s: No such file or directory\r\n", arg.c_str()); return; }
  if (n->dir)    { out.printf("cat: %s: Is a directory\r\n", arg.c_str()); return; }

  // Reading a secret is the moment worth alerting on, not the login.
  if (abs.endsWith("/shadow") || abs.endsWith("id_rsa") ||
      abs.endsWith("credentials.txt") || abs.endsWith("backup.sh")) {
    evLog(EV_COMMAND, SEV_ALERT, ip, 23, "read bait file %s", abs.c_str());
  }
  out.print(body.length() ? body : String("\r\n"));
}

// ---------------------------------------------------------------- dispatch ---

static bool execCommand(ShellSession& s, const String& raw, Print& out, uint32_t ip) {
  String cmd = raw;
  cmd.trim();
  if (!cmd.length()) return true;

  // Take only the first command of a chain for matching, but log the whole line.
  String head = cmd;
  int cut = head.indexOf(';');
  if (cut < 0) cut = head.indexOf("&&");
  if (cut > 0) head = head.substring(0, cut);
  head.trim();

  String verb = head, arg;
  int sp = head.indexOf(' ');
  if (sp > 0) { verb = head.substring(0, sp); arg = head.substring(sp + 1); arg.trim(); }

  // --- botnet loader path, checked first ---
  if (handleBusybox(cmd, out, ip)) return true;
  if (handleLoaderVerb(head, out)) return true;

  if (verb == "exit" || verb == "logout" || verb == "quit") {
    out.print("logout\r\n");
    return false;
  }

  // --- payload delivery: the highest-value capture ---
  if (verb == "wget" || verb == "curl" || verb == "tftp" || verb == "ftpget") {
    String url = extractUrl(cmd);
    evLog(EV_DOWNLOAD, SEV_ALERT, ip, 23, "%s payload from %s", verb.c_str(),
          hpSanitize(url, 100).c_str());
    // Hand the URL to the collector. It returns immediately — the fetch happens
    // on its own task so the attacker's session never stalls and never learns
    // how long we took.
    artQueue(url.c_str(), ip);
    if (verb == "wget") {
      out.printf("--2024-02-12 08:41:22--  %s\r\n", url.c_str());
      out.print("Resolving host... failed: Temporary failure in name resolution.\r\n");
      out.print("wget: unable to resolve host address\r\n");
    } else if (verb == "curl") {
      out.print("curl: (6) Could not resolve host\r\n");
    } else {
      out.print("tftp: server error: (1) File not found\r\n");
    }
    return true;
  }

  if (verb == "pwd")       { out.print(String(s.cwd) + "\r\n"); return true; }
  if (verb == "whoami")    { out.print(String(s.user) + "\r\n"); return true; }
  if (verb == "hostname")  { out.print(String(g_cfg.hostname) + "\r\n"); return true; }
  if (verb == "id") {
    bool root = strcmp(s.user, "root") == 0;
    out.printf("uid=%d(%s) gid=%d(%s) groups=%d(%s)%s\r\n",
               root ? 0 : 1000, s.user, root ? 0 : 1000, s.user,
               root ? 0 : 1000, s.user, root ? "" : ",27(sudo)");
    return true;
  }
  if (verb == "uname") {
    if (arg.length()) out.print("Linux " + String(g_cfg.hostname) +
                                " 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n");
    else out.print("Linux\r\n");
    return true;
  }
  if (verb == "uptime") {
    out.print(" 08:41:29 up 47 days,  3:12,  1 user,  load average: 0.08, 0.14, 0.09\r\n");
    return true;
  }
  if (verb == "date") { out.print("Mon Feb 12 08:41:29 UTC 2024\r\n"); return true; }

  if (verb == "ls" || verb == "dir" || verb == "ll") {
    doLs(s, verb == "ll" ? ("-l " + arg) : arg, out);
    return true;
  }
  if (verb == "cd") {
    String dest = vfsResolve(s.cwd, arg);
    String body;
    const VNode* n = vfsFind(dest, body);
    if (!n)            out.printf("bash: cd: %s: No such file or directory\r\n", arg.c_str());
    else if (!n->dir)  out.printf("bash: cd: %s: Not a directory\r\n", arg.c_str());
    else               hpCopy(s.cwd, sizeof(s.cwd), dest.c_str());
    return true;
  }
  if (verb == "cat" || verb == "head" || verb == "tail" || verb == "more" || verb == "less") {
    doCat(s, arg, out, ip);
    return true;
  }

  if (verb == "sudo" || verb == "su") {
    out.printf("[sudo] password for %s: ", s.user);
    s.stage = SH_SUDO;
    return true;
  }

  if (verb == "free") {
    out.print("               total        used        free      shared  buff/cache   available\r\n");
    out.print("Mem:        16266344     2841192     9930816      318024     3494336    12742048\r\n");
    out.print("Swap:        2097148           0     2097148\r\n");
    return true;
  }
  if (verb == "df") {
    out.print("Filesystem      Size  Used Avail Use% Mounted on\r\n");
    out.print("/dev/sda1       458G  187G  248G  44% /\r\n");
    out.print("tmpfs           7.8G  0     7.8G   0% /dev/shm\r\n");
    return true;
  }
  if (verb == "ps") {
    out.print("  PID TTY          TIME CMD\r\n");
    out.print(" 2841 pts/0    00:00:00 bash\r\n");
    out.print(" 2903 pts/0    00:00:00 ps\r\n");
    return true;
  }
  if (verb == "ifconfig" || (verb == "ip" && arg.startsWith("a"))) {
    out.print("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n");
    out.print("        inet 10.20.4.11  netmask 255.255.255.0  broadcast 10.20.4.255\r\n");
    out.print("        ether 00:15:5d:3a:8c:41  txqueuelen 1000  (Ethernet)\r\n");
    out.print("        RX packets 8412993  bytes 4127849201 (4.1 GB)\r\n");
    out.print("        TX packets 6120844  bytes 2884019283 (2.8 GB)\r\n");
    return true;
  }
  if (verb == "netstat" || verb == "ss") {
    out.print("Active Internet connections (only servers)\r\n");
    out.print("Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n");
    out.print("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n");
    out.print("tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN\r\n");
    out.print("tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n");
    return true;
  }
  if (verb == "history") {
    out.print("    1  ssh backup@10.20.4.19\r\n    2  mysql -u root -p\r\n"
              "    3  sudo systemctl restart nginx\r\n    4  history -c\r\n");
    return true;
  }
  if (verb == "env" || verb == "printenv") {
    out.printf("SHELL=/bin/bash\r\nUSER=%s\r\nHOME=/home/%s\r\nPWD=%s\r\nLANG=C.UTF-8\r\n",
               s.user, s.user, s.cwd);
    return true;
  }

  // Write-ish commands: succeed silently, as the real ones do.
  if (verb == "mkdir" || verb == "touch" || verb == "chmod" || verb == "chown" ||
      verb == "rm" || verb == "rmdir" || verb == "mv" || verb == "cp" ||
      verb == "kill" || verb == "export" || verb == "unset" || verb == "clear") {
    if (verb == "clear") out.print("\033[H\033[2J");
    return true;
  }
  if (verb == "echo") { out.print(arg + "\r\n"); return true; }

  if (verb == "apt" || verb == "apt-get" || verb == "yum" || verb == "dnf") {
    out.print("Reading package lists... Done\r\nBuilding dependency tree... Done\r\n");
    if (arg.startsWith("install")) out.print("E: Unable to locate package\r\n");
    return true;
  }
  if (verb == "systemctl" || verb == "service") {
    out.print("Failed to connect to bus: No such file or directory\r\n");
    return true;
  }

  out.printf("bash: %s: command not found\r\n", hpSanitize(verb, 40).c_str());
  return true;
}

// ------------------------------------------------------------- line feed ---

// Sessions that type forever are either a fuzzer or a stuck bot. Cap them.
static const uint16_t MAX_COMMANDS = 400;

bool shellFeedLine(ShellSession& s, const String& line, Print& out, uint32_t ip) {
  switch (s.stage) {
    case SH_LOGIN: {
      String u = hpSanitize(line, 30);
      if (!u.length()) { out.print("login: "); return true; }
      hpCopy(s.pendingUser, sizeof(s.pendingUser), u.c_str());
      s.stage = SH_PASSWORD;
      out.print("Password: ");
      return true;
    }

    case SH_PASSWORD: {
      String p = hpSanitize(line, 40);
      // The credential pair is the product here — record it as one unit so the
      // dashboard can rank "what are they guessing with".
      evLog(EV_LOGIN, SEV_NOTICE, ip, 23, "%s : %s",
            s.pendingUser, p.length() ? p.c_str() : "<empty>");
      hpCopy(s.user, sizeof(s.user), s.pendingUser);
      s.stage = SH_PROMPT;
      shellGreet(s, out);
      out.print(shellPrompt(s));
      return true;
    }

    case SH_SUDO: {
      String p = hpSanitize(line, 40);
      evLog(EV_LOGIN, SEV_ALERT, ip, 23, "sudo password for %s : %s",
            s.user, p.length() ? p.c_str() : "<empty>");
      out.print("\r\nSorry, try again.\r\n");
      s.stage = SH_PROMPT;
      out.print(shellPrompt(s));
      return true;
    }

    default: {
      String cmd = hpSanitize(line, HP_DETAIL_LEN - 24);
      if (cmd.length()) evLog(EV_COMMAND, SEV_NOTICE, ip, 23, "%s", cmd.c_str());
      bool keep = execCommand(s, cmd, out, ip);
      if (!keep) return false;
      if (++s.commands > MAX_COMMANDS) return false;
      if (s.stage == SH_PROMPT) out.print(shellPrompt(s));
      return true;
    }
  }
}
