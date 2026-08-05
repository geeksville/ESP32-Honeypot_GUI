# ESP32 Honeypot

A multi-port honeypot for ESP32. It impersonates a small Linux file server,
records everything an attacker types, retrieves the malware they try to install,
and shows all of it in a control panel served from the device itself.

Every screenshot below is this firmware running on an **ESP32-S3-N16R8**
(16 MB flash, 8 MB octal PSRAM) with live capture data.

![Dashboard](docs/dashboard.png)

---

## Contents

- [What it does](#what-it-does)
- [Hardware you need](#hardware-you-need)
- [Install the toolchain](#install-the-toolchain)
- [Flash it](#flash-it)
- [First-time setup](#first-time-setup)
- [Default credentials](#default-credentials)
- [Using the panel](#using-the-panel)
- [Artifact collector](#artifact-collector)
- [Alerts](#alerts)
- [Why only 8 ports](#why-only-8-ports)
- [Verified against nmap](#verified-against-nmap)
- [HTTP API](#http-api)
- [Troubleshooting](#troubleshooting)
- [How it is built](#how-it-is-built)

---

## What it does

- **Fourteen emulated services** — FTP, SSH, Telnet, SMTP, DNS, POP3, IMAP,
  HTTPS, SMB, MySQL, RDP, VNC, Redis, HTTP-alt. Eight can be armed at once
  ([why](#why-only-8-ports)). FTP, SMTP, POP3, IMAP and Redis hold a real
  conversation and capture credentials; the rest answer with protocol-accurate
  binary greetings.
- **An interactive fake shell** on telnet with a data-driven filesystem, real
  path resolution, and bait worth stealing: `/etc/shadow`, an SSH private key, a
  backup script with a hardcoded database password. Reading any of them raises an
  alert.
- **Botnet awareness.** Mirai-family loaders are the overwhelming majority of
  real telnet traffic. Their probe sequence (`enable`, `system`, `shell`, `sh`,
  `/bin/busybox <SIG>`) is answered byte-accurately — `<SIG>: applet not found`,
  exactly as real busybox replies — so the loader proceeds to the payload stage
  instead of hanging up. That stage is the part worth capturing.
- **Malware collection.** `wget`/`curl`/`tftp` URLs are fetched, hashed with
  SHA-256, identified by ELF architecture and stored for download.
- **Alerting** to Discord, Telegram, a JSON endpoint, or syslog.
- **A control panel** that runs permanently, on your network and on its own
  fallback access point.

## Hardware you need

| | |
|---|---|
| Board | Any ESP32. Developed and tested on **ESP32-S3-N16R8**. Environments also provided for classic ESP32 (`esp32dev`) and M5Stack AtomS3 (`atoms3`). |
| Cable | A USB **data** cable — many cheap cables are power-only and the board will never appear as a serial port. |
| Network | 2.4 GHz Wi-Fi. ESP32 does not do 5 GHz. |

ESP32-C6 (NanoC6) and C5 need Arduino core 3.x — use the
[pioarduino](https://github.com/pioarduino/platform-espressif32) platform fork
instead of `espressif32 @ ^6.6.0`.

## Install the toolchain

```bash
pip install platformio          # or: pipx install platformio
```

On Linux, add yourself to the group that owns serial ports, then log out and back
in (otherwise you will need `sudo` to flash):

```bash
sudo usermod -aG dialout $USER      # Debian/Ubuntu/Kali
sudo usermod -aG uucp $USER         # Arch
```

No libraries to install by hand — `ArduinoJson` is fetched automatically on the
first build and everything else ships with the Arduino ESP32 core.

## Flash it

```bash
git clone http://192.168.178.18:3030/cybercoon/honeypot.git
cd honeypot

pio run -e esp32s3 -t upload        # build + flash
pio device monitor                  # serial console at 115200 baud
```

Pick the environment that matches your board:

| Board | Command |
|---|---|
| ESP32-S3-N16R8 | `pio run -e esp32s3 -t upload` |
| Classic ESP32 (4 MB) | `pio run -e esp32dev -t upload` |
| M5Stack AtomS3 | `pio run -e atoms3 -t upload` |

If the port is not auto-detected, pass it:

```bash
pio run -e esp32s3 -t upload --upload-port /dev/ttyACM0
```

Find the port with `ls /dev/ttyACM* /dev/ttyUSB*` (Linux),
`ls /dev/cu.*` (macOS), or Device Manager (Windows). Boards that do not reset
automatically need the **BOOT** button held while you plug them in.

There is **no filesystem upload step**. The web UI is compiled into the firmware:
`tools/gen_ui.py` gzips `ui/index.html` into `src/ui_index.h` as a pre-build
step, so 52 KB of HTML becomes 15 KB of flash and can never drift out of sync
with the binary. Edit `ui/index.html` and rebuild — the header regenerates
itself.

> **ESP32-S3 N16R8 owners:** `board_build.arduino.memory_type = qio_opi` is
> already set for `env:esp32s3` and is required. These modules carry *octal*
> PSRAM; with the quad default the chip reports "PSRAM not found" and the event
> ring silently drops from 2048 entries in PSRAM to 128 in heap.

## First-time setup

**1. Power it on.** With no configuration stored it starts its own network. The
serial console tells you exactly what to connect to:

```
=== ESP32 Honeypot 2.0.0 ===
[boot] ESP32-S3, 309 KB heap, 8189 KB PSRAM
[events] ring holds 2048 events (385024 bytes, PSRAM)
[boot] no Wi-Fi configured yet

[wifi] first run — setup network is up
[wifi]   network : honeypot-setup
[wifi]   password: trapdoor123
[wifi]   panel   : http://192.168.4.1/
```

**2. Join `honeypot-setup`** from a phone or laptop, then open
**`http://192.168.4.1/`**.

**3. Open Settings** and fill in:

- **Wi-Fi network and password** — yours, so the device can join your LAN.
- **Panel password** — do this now. Until you set one the panel is open to
  anyone on the network, and the UI shows a red bar saying so.
- **Hostname the shell reports** — pick something that fits the network you are
  putting it on. A trap called `honeypot` catches nothing. Default is
  `srv-fileshare`.

![Settings](docs/settings.png)

**4. Save.** The device reboots into your network and arms the trap. Find its
address on the serial console, in your router's DHCP table, or at
`http://srv-fileshare.local/` (mDNS, using whatever hostname you set).

```
[wifi] joining BLUE OYSTER...
[wifi] joined, address 192.168.8.194 (-30 dBm)
[time] synced: Wed Aug  5 16:30:29 2026
[svc] armed :21    ProFTPD 1.3.8 (Debian)
[svc] armed :22    OpenSSH 8.9p1 Ubuntu
[svc] armed :23    Linux telnetd
...
```

That is it — the trap is live and the panel stays reachable while it runs.

If the configured network later disappears, the device brings the setup AP back
up and retries with backoff. It does not reboot, and it pauses retrying while
somebody is connected to the AP, because station scans knock the SoftAP off the
air.

## Default credentials

| What | Value | Change it in |
|---|---|---|
| Setup network (SSID) | `honeypot-setup` | `src/main.cpp` → `AP_SSID` |
| Setup network password | `trapdoor123` | `src/main.cpp` → `AP_PASS` |
| Panel URL, setup mode | `http://192.168.4.1/` | — |
| Panel URL, on your LAN | DHCP address or `http://srv-fileshare.local/` | Settings → hostname |
| **Panel password** | **none — unset on first boot** | Settings → Control panel |
| Fake shell login | **any username and password are accepted** | by design |

The shell accepting anything is deliberate: the point is to record what attackers
guess with, then let them in to see what they do next. Every attempt is logged as
a credential pair and ranked in the panel.

---

## Using the panel

**Bait** is the top section: one card per port showing the *exact greeting that
port sends on connect* — what an attacker actually reads off the wire. Click a
card to arm or disarm it. Changes apply immediately, with no reboot.

**Catch** is everything recorded, live. Filter by address, port or text; narrow
to notable events or alerts only; export the whole log as NDJSON or CSV.

![Catch](docs/catch.png)

Colour means something rather than decorating: **green is nominal**, **orange is
live/armed**, **red is an alert** — credential theft, a dropper URL, a path
traversal attempt. The layout works down to phone width.

<img src="docs/mobile.png" width="330" alt="Mobile layout">

## Artifact collector

When something runs `wget`, `curl` or `tftp` in the fake shell, the URL alone is
a weak indicator — it is usually dead within hours. The collector retrieves the
file, hashes it with SHA-256, identifies the target architecture from its ELF
header, deduplicates it and stores it for download.

![Artifacts](docs/artifacts.png)

**It ships disabled.** Fetching a dropper makes an outbound request to the
attacker's server, which confirms to them that your address is live. Turn it on
in **Settings → Artifacts** only if that trade is acceptable for your deployment.

Bounded by per-sample size (64 KB – 1 MB, default 256 KB), sample count (24) and
total bytes. Samples are served as `application/octet-stream` named by their
digest, so nothing can be opened by accident.

## Alerts

**Settings → Alerts** supports Discord, Telegram, a generic JSON endpoint for
SIEM ingest, and RFC 5424 syslog over UDP.

| Setting | Why it matters |
|---|---|
| Severity floor | A port scan should not page you at 3am. Default: logins and commands. |
| Cooldown | One scan touches every port at once; this stops a single visitor sending a hundred messages. |
| Send a test alert | Proves the destination works before you rely on it. |

Delivery runs on its own task, so a slow or unreachable webhook can never delay
the honeypot.

---

## Why only 8 ports

The Arduino ESP32 core is compiled with `CONFIG_LWIP_MAX_SOCKETS=16`, and that
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

The panel reports a clear error if you try to arm more. Lifting the limit means
moving off the BSD socket API onto raw lwIP `tcp_pcb` callbacks, which draw from
a separate pool.

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

**Known gaps:** RDP (3389) still reads as `tcpwrapped`, and SMB (445) returns
data nmap cannot match to a dialect. Both are binary protocols needing a fuller
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
# Sign in
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
        -d '{"password":"yourpassword"}' http://<device>/api/login \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

# Arm a different set of ports, no reboot
curl -X POST -H "X-Auth: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"ports":[21,22,23,25,445,3306,3389,8080]}' http://<device>/api/config

# Pull the whole capture as CSV
curl -H "X-Auth: $TOKEN" 'http://<device>/api/export?fmt=csv' -o events.csv
```

---

## Troubleshooting

**The board does not appear as a serial port.** Almost always a power-only USB
cable. Otherwise you may need a driver for the USB-serial chip (CP210x or CH340)
on Windows/macOS; boards with native USB (S3, C3) need none.

**Permission denied on `/dev/ttyACM0`.** You are not in the `dialout` group —
see [Install the toolchain](#install-the-toolchain). Log out and back in after
adding yourself.

**Upload fails / board not in bootloader.** Hold **BOOT**, tap **RESET**, release
**BOOT**, then run the upload again.

**"PSRAM not found" on an S3.** You are building an N16R8 module without
`board_build.arduino.memory_type = qio_opi`. It is set for `env:esp32s3`; copy it
if you added your own environment.

**It will not join your Wi-Fi.** ESP32 is 2.4 GHz only — a 5 GHz-only SSID will
never be found. Check the serial console: `[wifi] <ssid> not reachable, next try
in Ns` means the network was not seen at all.

**`honeypot-setup` is not visible.** The station radio and the SoftAP share one
antenna, so while the device retries a configured-but-absent network the beacon
drops out for seconds at a time. Rescan a few times, or erase the stored
configuration (below) for a rock-steady AP.

**Everything shows as `tcpwrapped`.** Too many ports armed — see
[why only 8 ports](#why-only-8-ports).

**Locked out, or you want a clean slate.** Settings → Device → "Erase
everything", or over USB:

```bash
pio run -e esp32s3 -t erase          # wipe the whole chip, then re-flash
```

To clear only stored settings and captures, keeping the firmware:

```bash
python3 ~/.platformio/packages/tool-esptoolpy/esptool.py \
  --chip esp32s3 --port /dev/ttyACM0 erase_region 0x810000 0x20000
```

**Statistics reset after a reboot.** Expected — the ring buffer and counters live
in RAM. The event log on flash is what persists; download it, or ship events to a
webhook or syslog collector.

---

## How it is built

```
src/hp_services.*    listeners, connection pool, banners, line protocols
src/hp_shell.*       fake filesystem and command emulation
src/hp_artifacts.*   payload retrieval, SHA-256, ELF classification
src/hp_events.*      event ring (PSRAM when available) and statistics
src/hp_store.*       LittleFS, NDJSON log, rotation, export
src/hp_notify.*      alert queue and delivery worker
src/hp_web.*         REST API, token auth, gzipped UI
src/main.cpp         boot, Wi-Fi supervision, task setup
ui/index.html        the control panel — source of src/ui_index.h
tools/gen_ui.py      gzips the UI into a PROGMEM header at build time
```

Honeypot listeners run on **core 1**; the control panel, Wi-Fi supervision, alert
delivery and artifact retrieval run on **core 0**. Nothing on the alert or
collector path can delay the listeners.

Connections are slots in a fixed pool, each pumped for microseconds per pass with
idle and absolute deadlines — no blocking reads anywhere, so a connection that
opens and says nothing cannot take a port offline.

Configuration is written via temp-file-and-rename so a power cut cannot corrupt
it. Events are appended as NDJSON and rotated with one retained generation, which
puts a hard ceiling on flash use. Exports stream in chunks, so a multi-megabyte
log never has to fit in RAM.

---

## Usage

This is a canary for a network you control. Do not expose it to the internet
without upstream filtering — it is a lightweight trap, not
[Cowrie](https://github.com/cowrie/cowrie).

MIT. Began as a rewrite of
[7h30th3r0n3/ESP32-Honeypot](https://github.com/7h30th3r0n3/ESP32-Honeypot);
no original code remains.
