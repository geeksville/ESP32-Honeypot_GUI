# ESP32 Honeypot v2

A multi-port honeypot for ESP32 that impersonates a small Linux file server,
records what attackers type, retrieves the malware they try to install, and
shows all of it in a control panel served from the device itself.

Rewritten from the original single-file sketch. Every screenshot below is the
real firmware running on an **ESP32-S3-N16R8** (16 MB flash, 8 MB octal PSRAM).

![Dashboard](docs/dashboard.png)

---

## Contents

- [Default credentials](#default-credentials)
- [What you need](#what-you-need)
- [Build and flash](#build-and-flash)
- [First run](#first-run)
- [The control panel](#the-control-panel)
- [Artifact collector](#artifact-collector)
- [Alerts](#alerts)
- [What changed from v1](#what-changed-from-v1)
- [The socket ceiling](#the-socket-ceiling)
- [Verified against nmap](#verified-against-nmap)
- [HTTP API](#http-api)
- [Troubleshooting](#troubleshooting)

---

## Default credentials

| What | Value | Change it in |
|---|---|---|
| Setup network (SSID) | `honeypot-setup` | `src/main.cpp` → `AP_SSID` |
| Setup network password | `trapdoor123` | `src/main.cpp` → `AP_PASS` |
| Panel URL, setup mode | `http://192.168.4.1/` | — |
| Panel URL, on your LAN | `http://<dhcp-address>/` or `http://srv-fileshare.local/` | hostname in Settings |
| **Panel password** | **none — unset on first boot** | Settings → Control panel |
| Fake shell login | **any username and password are accepted** | by design |

> The panel ships with **no password**. Until you set one, anyone on the network
> can disarm the trap or read what it caught, and the UI shows a red warning bar
> saying exactly that. Set one during first run.

The fake shell accepting any credentials is deliberate — the point is to record
what attackers guess with, then let them in to see what they do next. Whatever
they type is logged as a credential pair.

---

## What you need

- An ESP32 board. Tested on ESP32-S3-N16R8; environments are also provided for
  classic ESP32 (`esp32dev`) and M5Stack AtomS3 (`atoms3`).
- A USB data cable (many cheap cables are power-only).
- [PlatformIO](https://platformio.org/install/cli) — `pip install platformio`.

No manual library installation: `ArduinoJson` is pulled automatically, and
everything else ships with the Arduino ESP32 core.

## Build and flash

```bash
git clone https://github.com/HelixNewton/Honeypot.git
cd Honeypot/ESP32-Honeypot-v2

pio run -e esp32s3 -t upload      # build and flash
pio device monitor                 # watch the serial console at 115200
```

Pick the environment that matches your board: `-e esp32s3`, `-e esp32dev`, or
`-e atoms3`. If the upload port is not detected, pass it explicitly:

```bash
pio run -e esp32s3 -t upload --upload-port /dev/ttyACM0
```

The web UI is compiled into the firmware — `tools/gen_ui.py` gzips
`ui/index.html` into `src/ui_index.h` as a pre-build step, so there is **no
filesystem upload step** and no asset that can drift out of sync with the
binary. 52 KB of HTML becomes 15 KB of flash.

To edit the UI, change `ui/index.html` and rebuild; the header regenerates
automatically.

> **ESP32-S3 N16R8 owners:** `board_build.arduino.memory_type = qio_opi` is
> already set in `platformio.ini` and is required. These modules carry *octal*
> PSRAM; with the quad default the chip reports "PSRAM not found" and the event
> ring silently drops from 2048 entries in PSRAM to 128 in heap.

## First run

1. **Flash the board.** On boot with no configuration it starts its own network:

   ```
   [wifi] first run — setup network is up
   [wifi]   network : honeypot-setup
   [wifi]   password: trapdoor123
   [wifi]   panel   : http://192.168.4.1/
   ```

2. **Join `honeypot-setup`** from a phone or laptop and open `http://192.168.4.1/`.

3. **Open Settings** and fill in:
   - your Wi-Fi network and password,
   - a **panel password** (do this now),
   - optionally the hostname the fake shell reports — pick something that fits
     the network you are putting it on. A trap called `honeypot` catches nothing.

   ![Settings](docs/settings.png)

4. **Save.** The device joins your network and arms the trap. Find its address on
   the serial console, from your router, or at `http://srv-fileshare.local/`.

The panel stays reachable while the honeypot is armed — you do not have to choose
between running the trap and being able to read it.

If the configured network later disappears, the device brings the setup AP back
up and keeps retrying with backoff. It does not reboot, and it pauses retrying
while somebody is connected to the AP, because station scans knock the SoftAP off
the air.

---

## The control panel

**Bait** is the hero of the page: one card per port showing the *exact greeting
that port sends on connect*, whether it is armed, and how many times it has been
hit. Click a card to arm or disarm it — it takes effect immediately, with no
reboot.

**Catch** is everything recorded, live. Filter by address, port or text; narrow
to notable events or alerts only; export the whole log as NDJSON or CSV.

![Catch](docs/catch.png)

Colour carries meaning rather than decoration: **green is nominal**, **orange is
live/armed**, **red is an alert** (credential theft, a dropper URL, a path
traversal attempt). It works down to phone width.

<img src="docs/mobile.png" width="330" alt="Mobile layout">

---

## Artifact collector

When something runs `wget`, `curl` or `tftp` in the fake shell, the URL alone is
a weak indicator — it is usually dead within hours. The collector retrieves the
file, hashes it with SHA-256, identifies the target architecture from its ELF
header, deduplicates it and stores it for download.

![Artifacts](docs/artifacts.png)

**It is off by default.** Fetching a dropper makes an outbound request to the
attacker's server, which confirms to them that your address is live. Turn it on
in Settings → Artifacts only if that trade is acceptable for your deployment.

Bounded by per-sample size (64 KB – 1 MB, default 256 KB), sample count (24) and
total bytes. Samples are served as `application/octet-stream` named by their
digest, so nothing can be opened by accident.

## Alerts

Settings → Alerts supports **Discord**, **Telegram**, a **generic JSON endpoint**
for SIEM ingest, and **RFC 5424 syslog** over UDP. Set a severity floor so a port
scan does not page you, and a cooldown so one visitor cannot send a hundred
messages. "Send a test alert" proves the destination works before you rely on it.

Delivery happens on its own task, so a slow or unreachable webhook can never
delay the honeypot.

---

## What changed from v1

The original worked, but a handful of structural problems limited it:

| # | Problem in v1 | Fix |
|---|---|---|
| 1 | `startHoneypot()` was an infinite `while(true)` inside `setup()`; `loop()` never ran | Non-blocking connection pool on a dedicated FreeRTOS task |
| 2 | `honeypotLoop()` — holding all the good nmap-friendly banners — was **never called** | One code path; the banner table is the only source of truth |
| 3 | `readLine()` blocked forever, so one idle telnet connection froze **every** port | Per-connection idle and absolute deadlines, no blocking reads |
| 4 | The web UI existed only when Wi-Fi *failed*; once armed you could never read logs | Panel runs permanently, on the LAN and on the fallback AP |
| 5 | `POST /config` wrote the raw body to flash, unvalidated and unauthenticated | Schema validation, staged commit, token auth, login backoff |
| 6 | `GET /config` returned the **Wi-Fi password in plaintext** to anyone | Secrets never leave the device; the UI sends "unchanged" sentinels |
| 7 | The log grew without bound until flash filled and writes failed silently | NDJSON with rotation and one retained generation |
| 8 | The webhook POST was blocking and inline — every event stalled the honeypot | Queue plus worker task, severity floor, cooldown |
| 9 | Timestamps were `millis()`, useless for correlation | NTP with a configurable POSIX timezone |
| 10 | Telnet never echoed and never stripped IAC, corrupting every captured username | Full IAC state machine, correct echo, password suppression |
| 11 | `cd` was ~15 hardcoded cases; the fake filesystem was unmaintainable `if/else` | Data-driven VFS table with real path resolution |
| 12 | No rate limiting and no connection cap | Slot pool plus a logging throttle that never refuses a connection |

Beyond the fixes: Mirai-aware telnet, the artifact collector, conversational
FTP/SMTP/POP3/IMAP/Redis that capture credentials, and the new control panel.

**Botnet handling.** Mirai-family loaders are the overwhelming majority of real
telnet traffic. Their probe sequence (`enable`, `system`, `shell`, `sh`,
`/bin/busybox <SIG>`) is answered byte-accurately — `<SIG>: applet not found`,
exactly as real busybox replies — so the loader proceeds to the payload stage
instead of hanging up. That stage is the part worth capturing.

---

## The socket ceiling

The Arduino ESP32 core is compiled with `CONFIG_LWIP_MAX_SOCKETS=16`, and it
cannot be raised without rebuilding the IDF. **Every listener costs a socket that
an accepted connection then cannot have.**

```
8 honeypot listeners + 1 web listener + 6 live connections + 1 spare = 16
```

Exceed it and `accept()` starts failing, which a scanner reports as `tcpwrapped`
on every port — the most obvious tell a honeypot can give. Measured on hardware:

| Ports armed | nmap result |
|---|---|
| 14 | `tcpwrapped` on 13 of 14 — sockets exhausted |
| 8 | 7 of 8 identified as real services |

This is very likely why v1's own source comment reads *"Nmap-friendly banners
(almost working on it)"* — it opens 13 listeners plus an async web server and
starves itself.

`HP_MAX_PORTS` is therefore **8**, and the UI reports a clear error if you try to
arm more. Lifting it means moving off the BSD socket API onto raw lwIP `tcp_pcb`
callbacks, which draw from a separate pool.

## Verified against nmap

Real `nmap -sT -sV` against the device with 8 ports armed:

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

**Known gaps:** RDP (3389) still reads as `tcpwrapped`, and SMB (445) returns data
nmap cannot match to a dialect. Both are binary protocols needing a fuller
handshake than one canned response.

---

## HTTP API

Everything except `/` and `/api/login` requires `X-Auth: <token>` once a panel
password is set.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/state` | Status, statistics and events after `?cursor=` |
| `GET` / `POST` | `/api/config` | Read / patch settings (secrets never returned) |
| `POST` | `/api/login` | Exchange the password for a session token |
| `GET` | `/api/scan` | Nearby Wi-Fi networks |
| `GET` | `/api/export?fmt=ndjson\|csv` | Stream the capture log |
| `GET` | `/api/artifacts` | Collected samples |
| `GET` | `/api/artifact?sha=` | Download one sample |
| `POST` | `/api/artifacts/clear` | Delete all samples |
| `POST` | `/api/test-alert` | Prove the alert destination works |
| `POST` | `/api/clear-log` · `/api/reboot` · `/api/reset` | Maintenance |

```bash
# Arm a different set of ports without rebooting
curl -X POST -H 'Content-Type: application/json' \
     -d '{"ports":[21,22,23,25,445,3306,3389,8080]}' \
     http://<device>/api/config

# Pull the whole capture as CSV
curl -H "X-Auth: $TOKEN" 'http://<device>/api/export?fmt=csv' -o events.csv
```

---

## Troubleshooting

**"PSRAM not found" on an S3.** You are building an N16R8 module without
`board_build.arduino.memory_type = qio_opi`. It is set for `env:esp32s3`; if you
added your own environment, copy it across.

**`honeypot-setup` is not visible.** The station radio and the SoftAP share one
antenna, so while the device is retrying a configured-but-absent network the
beacon drops out for seconds at a time. Rescan a few times, or erase the stored
configuration (below) to get a rock-steady AP.

**Everything shows as `tcpwrapped`.** Too many ports armed — see
[the socket ceiling](#the-socket-ceiling). Keep it to 8.

**Locked out / want a clean slate.** Settings → Device → "Erase everything", or
over USB:

```bash
pio run -e esp32s3 -t erase      # wipes the whole chip, then re-flash
```

To clear only the stored settings and captures, keeping the firmware:

```bash
python3 ~/.platformio/packages/tool-esptoolpy/esptool.py \
  --chip esp32s3 --port /dev/ttyACM0 erase_region 0x810000 0x20000
```

**Statistics reset after a reboot.** Expected: the ring buffer and counters live
in RAM. The event log on flash is what persists — download it, or ship events to
a webhook or syslog collector.

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
tools/gen_ui.py      gzips the UI into a PROGMEM header at build time
```

Honeypot listeners run on core 1; the control panel, Wi-Fi supervision, alerts
and artifact retrieval run on core 0. Nothing on the alert or collector path can
delay the listeners.

A v1 SPIFFS configuration is migrated automatically on first boot.

---

## Notes

This is a canary for a network you control. Do not expose it to the internet
without upstream filtering — it is a lightweight trap, not Cowrie.

MIT, as the original.
