# ESP32 Honeypot v2

A multi-port honeypot for ESP32 that emulates a small Linux file server, captures
what attackers type, retrieves the malware they try to install, and shows all of
it in a control panel served from the device itself.

Rewritten from the original single-file sketch. Verified on real hardware:
**ESP32-S3-N16R8** (16 MB flash, 8 MB octal PSRAM).

---

## What changed from v1

The original worked, but a handful of structural problems limited it. Each of
these is fixed here:

| # | Problem in v1 | Fix |
|---|---|---|
| 1 | `startHoneypot()` was an infinite `while(true)` inside `setup()`; `loop()` never ran | Non-blocking connection pool pumped from a dedicated FreeRTOS task |
| 2 | `honeypotLoop()` — containing all the good nmap-friendly banners — was **never called** | Single code path; the banner table is the only source of truth |
| 3 | `readLine()` blocked forever. One idle telnet connection froze **every** port | Per-connection idle and absolute deadlines, no blocking reads |
| 4 | Web UI existed only when Wi-Fi *failed*; once armed you could never read logs | Panel runs permanently, on the LAN and on the fallback AP |
| 5 | `POST /config` wrote the raw body to flash with no validation and no auth | Schema validation, staged commit, token auth, login backoff |
| 6 | `GET /config` returned the **Wi-Fi password in plaintext** to anyone | Secrets never leave the device; UI sends "unchanged" sentinels |
| 7 | Log file grew without bound until flash filled and writes failed silently | NDJSON with rotation and one retained generation (hard ceiling) |
| 8 | Webhook `POST` was blocking and inline — every event stalled the honeypot | Queue + worker task, severity filter, cooldown |
| 9 | Timestamps were `millis()`, useless for correlation | NTP with configurable POSIX timezone |
| 10 | Telnet never echoed and never stripped IAC, corrupting every captured username | Full IAC state machine, correct echo, password suppression |
| 11 | `cd` was ~15 hardcoded cases; the fake filesystem was unmaintainable `if/else` | Data-driven VFS table with real path resolution |
| 12 | No rate limiting, no connection cap | Slot pool + logging throttle that never refuses a connection |

---

## The constraint that shapes everything

The Arduino ESP32 core is compiled with `CONFIG_LWIP_MAX_SOCKETS=16`, and it
cannot be raised without rebuilding the IDF. **Every listener costs a socket that
an accepted connection then cannot have.**

```
8 honeypot listeners + 1 web listener + 6 live connections + 1 spare = 16
```

Exceed it and `accept()` starts failing, which a scanner reports as `tcpwrapped`
on every port — the most obvious tell a honeypot can give. This is measurable:

| Ports armed | nmap result |
|---|---|
| 14 | `tcpwrapped` on 13 of 14 — sockets exhausted |
| 8 | 7 of 8 identified as real services |

This is very likely why v1's own source comment reads *"Nmap-friendly banners
(almost working on it)"* — it opens 13 listeners plus an async web server and
starves itself.

`HP_MAX_PORTS` is therefore **8**. Raising it requires moving off the BSD socket
API onto raw lwIP `tcp_pcb` callbacks, which use a separate pool.

---

## Verified behaviour

Real `nmap -sT -sV` against the device, 8 ports armed:

```
21/tcp   open  ftp
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.5 (Ubuntu Linux; protocol 2.0)
23/tcp   open  telnet
25/tcp   open  smtp     Postfix smtpd
445/tcp  open  microsoft-ds?
3306/tcp open  mysql    MySQL 8.0.35-0ubuntu0.22.04.1
3389/tcp open  tcpwrapped
8080/tcp open  http     Apache httpd 2.4.52 ((Ubuntu))
```

Known gaps: RDP (3389) still reads as `tcpwrapped`, and SMB (445) returns data
nmap cannot match to a dialect. Both are binary protocols that need a fuller
handshake than a single canned response.

---

## Features

**Services.** FTP, SSH, Telnet, SMTP, DNS, POP3, IMAP, HTTPS, SMB, MySQL, RDP,
VNC, Redis, HTTP-alt. FTP/SMTP/POP3/IMAP/Redis hold a real conversation and
capture credentials; the rest answer with protocol-accurate binary greetings.

**Shell.** Data-driven fake filesystem with proper path resolution (`..`, `~`,
absolute and relative). Bait includes `/etc/shadow`, an SSH private key, a backup
script with a hardcoded database password, and a credentials file — reading any
of them raises an alert.

**Botnet-aware.** Mirai-family loaders are the overwhelming majority of real
telnet traffic. Their probe sequence (`enable`, `system`, `shell`, `sh`,
`/bin/busybox <SIG>`) is answered byte-accurately — `<SIG>: applet not found`, as
real busybox replies — so the loader proceeds to the payload stage instead of
hanging up, which is the part worth capturing.

**Artifact collector** (off by default). When something runs `wget`/`curl`/`tftp`,
the URL is handed to a worker task that retrieves the file, hashes it with
SHA-256, identifies it from its ELF header (architecture included), deduplicates
it, and stores it for download. Bounded by per-sample size, sample count and
total bytes.

> Retrieving a dropper makes an outbound request to the attacker's server, which
> confirms the address is live. That is why it ships disabled.

**Alerts.** Discord, Telegram, generic JSON (for SIEM ingest), or RFC 5424 syslog
over UDP. Severity floor and cooldown so one port scan cannot send a hundred
messages.

**Storage.** LittleFS. Config written via temp-file + rename so a power cut
cannot corrupt it. Events as NDJSON, exportable as NDJSON or CSV, streamed in
chunks so a multi-megabyte log never has to fit in RAM. A v1 SPIFFS config is
migrated automatically on first boot.

---

## Build

```bash
pio run -e esp32s3 -t upload && pio device monitor
```

The UI is compiled into the firmware — `tools/gen_ui.py` gzips `ui/index.html`
into `src/ui_index.h` as a pre-build step, so there is no filesystem upload and
no asset that can drift from the binary. 52 KB of HTML becomes 15 KB of flash.

Environments: `esp32s3` (16 MB / octal PSRAM), `esp32dev`, `atoms3`.
ESP32-C6/C5 need Arduino core 3.x via the pioarduino platform fork.

> On N16R8 boards `board_build.arduino.memory_type = qio_opi` is required.
> Without it the chip reports "PSRAM not found" and the event ring silently
> falls back to 128 entries in heap instead of 2048 in PSRAM.

## First run

1. Flash. The device brings up `honeypot-setup` / `trapdoor123`.
2. Open `http://192.168.4.1/`, enter your Wi-Fi details, **set a panel password**.
3. It joins your network and arms the trap. The panel stays reachable there.

If the configured network disappears the device keeps the setup AP up and retries
with backoff — it does not reboot, and it pauses retrying while someone is
connected to the AP, because station scans knock the AP off the air.

---

## HTTP API

All endpoints except `/` and `/api/login` require `X-Auth: <token>` once a panel
password is set.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/state` | Status, stats and events after `?cursor=` |
| `GET`/`POST` | `/api/config` | Read / patch settings (secrets never returned) |
| `POST` | `/api/login` | Exchange password for a session token |
| `GET` | `/api/scan` | Nearby Wi-Fi networks |
| `GET` | `/api/export?fmt=ndjson\|csv` | Stream the capture log |
| `GET` | `/api/artifacts` | Collected samples |
| `GET` | `/api/artifact?sha=` | Download one sample |
| `POST` | `/api/artifacts/clear` | Delete all samples |
| `POST` | `/api/test-alert` | Prove the alert destination works |
| `POST` | `/api/clear-log`, `/api/reboot`, `/api/reset` | Maintenance |

---

## Layout

```
src/hp_services.*    listeners, connection pool, banners, line protocols
src/hp_shell.*       fake filesystem and command emulation
src/hp_artifacts.*   payload retrieval, SHA-256, ELF classification
src/hp_events.*      event ring (PSRAM when available) and statistics
src/hp_store.*       LittleFS, NDJSON log, rotation, export
src/hp_notify.*      alert queue and delivery worker
src/hp_web.*         REST API, token auth, gzipped UI
ui/index.html        the control panel (source of src/ui_index.h)
```

Tasks: honeypot listeners on core 1; control panel, Wi-Fi supervision, alerts and
artifact retrieval on core 0. Nothing on the alert or collector path can delay
the listeners.

---

## Notes

Statistics are since-boot (RAM); the event log on flash is what persists.

This is a canary for a network you control. Do not expose it to the internet
without upstream filtering — it is a lightweight trap, not Cowrie.

MIT, as the original.
