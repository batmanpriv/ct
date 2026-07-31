<p align="center">
  <img src="https://github.com/user-attachments/assets/e9de135d-5689-4d55-badf-3a84e74beadf" alt="CT Logo" width="200">
</p>

<h1 align="center"> CT - Check Test</h1>

<p align="center">
Version: 1.5.1
</p>

<p align="center">
  English | <a href="readmefa.md">فارسی</a>
</p>


[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/batmanpriv/CheckTest)

**CT** is a fast, flexible, multi-purpose network testing suite written in Go. It brings together DNS benchmarking, proxy checking, MTProto testing, Xray/V2Ray config validation, public source scraping, and **Cloudflare IP scanning** in one powerful tool.

<p align="center">
  <img src="https://github.com/user-attachments/assets/0413df28-3e25-4d35-b03b-df09fbcede0c" alt="CT Banner" width="100%">
</p>

***

## Table of Contents

- [Overview](#overview)
- [Why CT](#why-ct)
- [What's New in 1.5.1](#whats-new-in-151)
- [Features](#features)
- [Modules](#modules)
- [Interactive Mode](#interactive-mode)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Cloudflare Scanner](#cloudflare-scanner)
- [Input Formats](#input-formats)
- [Output Files](#output-files)
- [Scraper System](#scraper-system)
- [Update System](#update-system)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Changelog](#changelog)
- [License](#license)

***

## Overview

CT is built for users who need a single command-line tool to test network quality, validate proxy and Xray configs, manage scraping sources, scan Cloudflare IPs, and keep everything updated without leaving the terminal.

It is designed to be:
- fast for large lists,
- practical for daily use,
- easy to extend,
- and comfortable in both scripted and interactive workflows.

### Why CT

- **All-in-One** — DNS, proxy, MTProto, Xray, scraper, Cloudflare scanner, and update workflow in one binary.
- **Interactive** — A cleaner terminal UI with arrow-key navigation and number support.
- **Smart Defaults** — Prompts appear only when needed.
- **Cross-Platform** — Windows, Linux, and macOS support.
- **Concurrent** — Multi-threaded checks for speed.
- **System-Aware** — Can apply best DNS or proxy settings directly.
- **Source-Managed** — Scraper sources can be added, removed, reloaded, and displayed from within the app.
- **Cloudflare Ready** — Advanced IP scanner with real-time results and multiple output formats.

***

## What's New in 1.5.1

This major release introduces **Proxy Configuration Testing** — a powerful feature that lets you test actual proxy configs (VMess, VLESS, Trojan, Shadowsocks) against live Cloudflare IPs.

### 1) Proxy Configuration Testing (Major New Feature)

The scanner can now test real proxy configurations against candidate IPs. Instead of just finding Cloudflare IPs, you can now find IPs that actually **work with your specific proxy config**.

**Supported Config Formats:**
- **VMess** (`vmess://`) — Full JSON parsing with base64 decoding
- **VLESS** (`vless://`) — URI-style with query parameters
- **Trojan** (`trojan://`) — URI-style with query parameters
- **Shadowsocks** (`ss://`) — URI-style with base64 decoding
- **Base64-encoded subscription lists** — Auto-detects and expands multiple configs

**How It Works:**
- The scanner parses your proxy config and extracts protocol, UUID, host, port, SNI, and other parameters
- Each candidate IP is tested by connecting through it with your config
- Real TLS/WebSocket handshakes verify the config actually works
- The IP in the config is automatically substituted with each candidate IP
- If a config works, it's saved with the candidate IP substituted

**New CLI Flags:**
```bash
-config <string|file>           Proxy config to test (VMess, VLESS, Trojan, SS)
-config-test-timeout <seconds>  Timeout for config tests (default: timeout+3)
-no-auto-subnet                 Disable automatic subnet fallback
-subnet-prefix <num>            Prefix length for auto-subnet (default: 24)
```

### 2) Smart Source Selection & Auto-Subnet

When you supply a proxy config, the scanner intelligently adjusts its behavior:

- **Domain Detection**: If the config uses a domain (e.g., `example.com`), the scanner uses it as the test domain automatically
- **Cloudflare Detection**: Analyzes security settings to detect if the config is behind Cloudflare
- **Auto-Subnet Fallback**: If the config has a bare IP and you're scanning Cloudflare ranges, it automatically switches to scanning that IP's own subnet (`/24` by default)
- **Port Auto-Add**: The config's port is automatically added to the scan list
- **Two-Pass Scanning**: First tries Cloudflare ranges, then falls back to the config's own subnet if no working IPs are found

### 3) New Output Files for Config Testing

When using `-config`, the scanner generates specialized output files:

- **`config_tested_ips_YYYYMMDD_HHMMSS.txt`** — All IP:ports that were tested
- **`config_tested_success_YYYYMMDD_HHMMSS.txt`** — Working configs with candidate IP substituted (ready to use!)

### 4) Extended Scan Results

New fields added to scan results for config testing:

| Field | Description |
|-------|-------------|
| `ConfigTested` | Whether the config was tested on this IP |
| `ConfigTestOK` | Whether the config worked (true/false) |
| `ConfigTestError` | Error message if config test failed |
| `ConfigTestMs` | Config test duration in milliseconds |
| `ConfigFinalURI` | Final config URI with candidate IP substituted |

### 5) Improved Stop-After Logic

The `-stop-after` flag now works intelligently with config testing:

- When `-config` is set, "good" means the config **actually tested OK** on that IP
- Not just the generic score — real config validation
- Stops as soon as you have N working configs

### 6) Enhanced Live Display

The top results table now shows a `Cfg` column:

- **✓** (green) — Config worked on this IP
- **✗** (red) — Config failed on this IP
- **-** (white) — Config not tested

### 7) WebSocket Support

For configs with `network: ws` (WebSocket):

- The scanner performs a **WebSocket upgrade handshake** after TLS
- Verifies the edge accepts WebSocket connections on the specified path
- Checks for `HTTP 101 Switching Protocols` response
- Ensures your WebSocket-based configs work properly

### 8) Subscription List Support

The scanner can now handle base64-encoded subscription lists:

- Auto-detects if input is base64
- Expands to multiple config lines
- Each config is tested individually
- Supports both file paths and direct base64 strings

---

## Features

### DNS Benchmark

- Multi-domain testing.
- UDP and TCP support.
- DNS-over-TLS and DNS-over-HTTPS support.
- HTTP verification for extra confidence.
- Speed-based and score-based sorting.
- System DNS apply support.
- Useful for comparing public resolvers quickly.

### Proxy Checker

- HTTP, HTTPS, SOCKS4, and SOCKS5 support.
- Auto-detection or manual type selection.
- Concurrent testing for large proxy lists.
- Optional proxy download and scraping flows.
- Best proxy application support.
- Designed for speed, accuracy, and flexible workflows.

### MTProto Checker

- Telegram MTProto proxy validation.
- Multiple input formats.
- Latency checks.
- Real-time valid proxy saving.
- Public source download support.
- Useful for checking Telegram proxy lists quickly.

### Xray Config Checker

- VLESS, VMESS, Trojan, and Shadowsocks support.
- Transport support for WebSocket, gRPC, XHTTP, and HTTPUpgrade.
- TLS and Reality handling.
- Optional HTTP test URL.
- Deduplication and GeoIP location detection.
- Automatic alive-config export.

### Cloudflare IP Scanner

- **Fast default ranges**: `104.16.0.0/13`, `104.24.0.0/14`, `172.64.0.0/13`
- **Full comprehensive ranges**: 22+ Cloudflare CIDR ranges including IPv6.
- **Real-time results**: Live table updates as IPs are found.
- **Port scanning**: Configurable port lists (default: 443, 80, 2053, 2083, 2087, 2096, 8443).
- **Automatic validation**: Detects Cloudflare via headers, TLS, and server responses.
- **Protocol detection**: HTTP/2, HTTP/3 support identification.
- **Latency measurement**: Real-time latency tracking with color coding.
- **Concurrent workers**: Configurable thread count for speed.
- **IP limits**: Configurable maximum IPs per range.
- **Multiple outputs**: JSON (full), CSV (spreadsheet), TXT (IP:Port).
- **Live saving**: Valid IPs saved in real-time to `valid_ips_YYYYMMDD_HHMMSS.txt`.
- **Custom ranges**: Scan specific CIDR ranges or IP files.
- **Color-coded output**: Visual feedback with progress, ETA, and sorted results.
- **Proxy Config Testing** (New): Test actual VMess/VLESS/Trojan/SS configs.

### Scraper Utility

- Add/remove sources.
- Reload internal source config.
- Show current config.
- Run scraping directly.
- Supports source-driven workflows.

### Update System

- Checks online version file.
- Compares local and remote versions.
- Supports Go-based install update.
- Windows release binary fallback.
- Git clone and build fallback when needed.

***

## Modules

### DNS Benchmark

The DNS module measures resolver responsiveness and capability. It can run simple DNS tests or extended HTTP-based validation depending on the selected mode.

### Proxy Checker

The proxy module checks whether proxies are alive, what type they are, and how they perform under concurrency.

### MTProto Checker

This module validates MTProto proxies and can auto-download from public sources for quick testing.

### Xray Checker

This module tests Xray/V2Ray configs by starting the core and validating real connectivity.

### Cloudflare Scanner

This module scans Cloudflare IP ranges, validates live IPs, and provides real-time results. It supports multiple ports, concurrent workers, and various output formats. **New in 1.5.1**: Test actual proxy configs against candidate IPs and save working configs automatically.

### Scraper

This module manages source lists and supports scraping workflow directly from inside CT.

### Update Checker

This module keeps CT up to date by checking the remote version and running the best available update path.

***

## Interactive Mode

Interactive mode is the easiest way to use CT if you do not want to remember flags.

### Main menu

- DNS Benchmark
- Proxy Checker
- MTProto Checker
- Xray Checker
- Scraper
- **Cloudflare Scanner**
- Check Update
- Exit

### Interactive behavior

- The screen is cleared at startup.
- The banner is rendered at the top.
- The cursor is hidden while navigating menus.
- The menu can be used with arrow keys.
- Number input can also be supported for quick selection.
- Prompts only appear when relevant.

***

## Installation

### Using Go Install

```bash
go install github.com/batmanpriv/ct@latest
```

### Build from Source

```bash
git clone https://github.com/batmanpriv/ct.git
cd ct
go build -o ct .
```

### Windows Release

If you are on Windows and prefer a binary, download the release file from GitHub Releases.

***

## Quick Start

### DNS Benchmark

```bash
ct dns resolvers.txt
```

### DNS with HTTP testing

```bash
ct dns resolvers.txt -mode 1 -domains "cloudflare.com,google.com,github.com"
```

### Proxy Checking

```bash
ct proxy proxies.txt
```

### MTProto Testing

```bash
ct mtproto mtproto.txt
```

### Xray Testing

```bash
ct xray configs.txt
```

### Cloudflare Scanner

```bash
# Quick scan with default settings
ct cf scan

# Scan with 200 workers and custom ports
ct cf scan -workers 200 -ports 443,8443,2096

# Test a proxy config against Cloudflare IPs (NEW!)
ct cf scan -config "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQtaGVyZSJ9" -stop-after 5

# Test configs from a file (NEW!)
ct cf scan -config configs.txt -workers 300 -stop-after 10

# Save working configs with candidate IPs substituted (NEW!)
ct cf scan -config "trojan://password@example.com:443?security=tls&sni=example.com" -output working_configs.json

# Auto-subnet fallback (NEW!)
ct cf scan -config "vless://uuid@1.2.3.4:443?security=tls&sni=example.com" -subnet-prefix 24

# Disable auto-subnet (NEW!)
ct cf scan -config "vmess://..." -no-auto-subnet

# Scan from file and sort by latency
ct cf scan -source custom:ips.txt -sort latency

# Full scan with all ranges
ct cf scan -source cloudflare_all

# Save results as CSV
ct cf scan -format csv -output scan.csv

# With speed test and geoip
ct cf scan -geoip GeoLite2-City.mmdb -speed
```

### Scraper

```bash
ct scrape run
```

### Update Check

```bash
ct check-update
```

***

## Command Reference

### DNS

```bash
ct dns [file]
ct dns apply-best
ct dns status
```

### Proxy

```bash
ct proxy [file]
ct proxy download
ct proxy scrape
ct proxy apply-best
ct proxy set status
```

### MTProto

```bash
ct mtproto [file]
ct mtproto download
```

### Xray

```bash
ct xray [file]
ct xray download
ct xray add-source <url>
```

### Scraper

```bash
ct scrape
ct scrape run
ct scrape add-source
ct scrape remove-source
ct scrape reload
ct scrape show-config
```

### Cloudflare Scanner

```bash
ct cf scan [flags]
```

Flags:
- `-source` — IP sources: `cloudflare`, `cloudflare_all`, `bgp`, `ipv6`, or `custom:file.txt`
- `-workers` — Number of workers (default: 100)
- `-ports` — Ports to scan (comma-separated)
- `-domain` — Test domain for validation
- `-output` — Output file path
- `-format` — Output format: `json`, `csv`, `txt`
- `-geoip` — GeoIP database path
- `-speed` — Enable speed test
- `-timeout` — HTTP/TLS timeout in seconds
- `-port-timeout` — Port scan timeout in seconds
- `-max` — Max results to show
- `-sort` — Sort by: `score`, `latency`
- `-quiet` — Disable real-time output
- `-noprogress` — Disable progress
- `-nocolor` — Disable colors

**New in 1.5.1:**
- `-config <string|file>` — Proxy config to test (VMess, VLESS, Trojan, SS)
- `-config-test-timeout <seconds>` — Timeout for config tests
- `-no-auto-subnet` — Disable automatic subnet fallback
- `-subnet-prefix <num>` — Prefix length for auto-subnet (default: 24)

### Update

```bash
ct check-update
```

***

## Cloudflare Scanner

The Cloudflare scanner is a powerful tool for discovering working Cloudflare IPs. It scans ranges, validates live IPs, and provides real-time feedback.

### Features

- **Fast scanning**: Multi-threaded with configurable workers.
- **Real-time results**: Live table updates as IPs are found.
- **Automatic validation**: Detects Cloudflare via:
  - HTTP headers (`CF-Ray`, `CF-Cache-Status`)
  - TLS certificates (issuer, SAN)
  - Server responses
- **Protocol detection**: HTTP/2 and HTTP/3 support.
- **Latency measurement**: TCP connect latency with color coding.
- **Live saving**: IPs saved to `valid_ips_*.txt` in real-time.
- **Multiple outputs**:
  - JSON: Full details (40+ fields)
  - CSV: Spreadsheet format
  - TXT: Simple IP:Port list
- **Custom ranges**: Scan specific CIDR ranges.
- **IP files**: Scan IPs from a text file.
- **Cloudflare detection**: Identifies Cloudflare IPs with high accuracy.
- **Color-coded**: Beautiful terminal output with progress and ETA.
- **Proxy Config Testing** (New in 1.5.1): Test actual VMess/VLESS/Trojan/SS configs.

### Default Ranges

Fast scan (default):
- `104.16.0.0/13`
- `104.24.0.0/14`
- `172.64.0.0/13`

Comprehensive scan (`cloudflare_all`):
- All 22+ Cloudflare IPv4 and IPv6 ranges.

### Proxy Config Testing (New in 1.5.1)

The scanner can now test real proxy configurations against candidate IPs.

**Supported Configs:**
- VMess (`vmess://`)
- VLESS (`vless://`)
- Trojan (`trojan://`)
- Shadowsocks (`ss://`)
- Base64-encoded subscription lists

**What it does:**
1. Parses your config and extracts protocol, UUID, host, port, SNI
2. Each candidate IP is tested by connecting through it with your config
3. Real TLS/WebSocket handshakes verify the config actually works
4. The IP in the config is automatically substituted with each candidate IP
5. Working configs are saved with the candidate IP substituted

**Example Output:**
```
Config test enabled: will verify vmess configs on IPs that pass validation
Config test: added the config's own port :443 to the scan port list
Config test: example.com looks CDN-fronted (security=tls) - using it as validation domain

[Scanning...]

Config test: 1245 tested, 23 succeeded
Working configs saved to: config_tested_success_20260131_150405.txt
```

### Scoring System

- **10 pts**: IP is alive
- **25 pts**: Cloudflare confirmed
- **10 pts**: HTTP/2 supported
- **15 pts**: HTTP/3 supported
- **Up to 20 pts**: Low latency (<30ms)
- **Up to 10 pts**: No packet loss
- **Up to 10 pts**: High speed

Total score: 0-100

### Color Legend

- **Latency**: Green (<150ms), Yellow (150-300ms), Red (>300ms)
- **Score**: Green (≥70), Yellow (40-69), Red (<40)
- **CF/H2/H3**: Green (✓ supported), Red (✗ not supported)
- **Cfg** (New): Green (✓ config works), Red (✗ config fails), White (- not tested)

***

## Input Formats

### DNS Server List

```txt
1.1.1.1
8.8.8.8
9.9.9.9
[2001:4860:4860::8888]:53
```

### Proxy List

```txt
http://user:pass@host:port
https://host:port
socks5://host:port
socks4://host:port
host:port
```

### MTProto List

```txt
https://t.me/proxy?server=example.com&port=443&secret=...
tg://proxy?server=example.com&port=443&secret=...
server=example.com port=443 secret=...
example.com 443 secret
```

### Xray/Proxy Config List (New in 1.5.1)

```txt
vless://...
vmess://...
trojan://...
ss://...
```

### Cloudflare IP File

```txt
# IPs or CIDR ranges, one per line
104.16.0.1
104.16.0.0/13
172.64.0.0/13
```

***

## Output Files

### DNS

- Valid resolver lists.
- Optional JSON results.

### Proxy

- Valid proxies saved by module logic.

### MTProto

- `valid_mtproto.txt`

### Xray

- `alive_configs.txt`

### Cloudflare Scanner

- `valid_ips_YYYYMMDD_HHMMSS.txt` — Real-time IP:Port list
- `{user-defined}.json` — Full details (40+ fields)
- `{user-defined}.csv` — Spreadsheet format
- `{user-defined}.txt` — IP:Port list

**New in 1.5.1 (Config Testing):**
- `config_tested_ips_YYYYMMDD_HHMMSS.txt` — All IP:ports tested
- `config_tested_success_YYYYMMDD_HHMMSS.txt` — Working configs with candidate IP substituted

### Scraper

- Config and scraped output files in `output/`

***

## Scraper System

The scraper module is one of the most useful additions in this version. It gives you direct control over the source list instead of relying only on static defaults.

### What it can do

- Add a source URL.
- Remove a source URL.
- Reload the internal default config.
- Show current source settings.
- Run scraping immediately.

### Example flow

```bash
ct scrape
```

Inside the menu, you can:
- add a new source,
- remove a broken source,
- reload defaults,
- inspect the active config,
- or run the scraper.

### Direct run

```bash
ct scrape run
```

This is useful when you want the scraper to execute immediately without opening the source management menu.

***

## Update System

CT now includes a built-in update workflow.

### Update process

1. Read the latest version from the remote version file.
2. Compare it with the local `VERSION`.
3. If the versions differ:
   - try `go install github.com/batmanpriv/ct@vX.Y.Z`,
   - if Go is unavailable and the platform is Windows, download the release binary,
   - if that fails too, clone the repository and build from source.

### Why this matters

This gives users multiple recovery paths:
- Go users get the easiest update flow.
- Windows users get a binary fallback.
- Everyone else gets a source-build fallback.

***

## Performance

CT uses concurrency heavily to keep testing fast.

### General notes

- DNS, proxy, MTProto, Xray, and Cloudflare checks all use worker-based execution.
- Smart defaults reduce manual overhead.
- Cached and fallback-based flows reduce repeated work.
- Interactive prompts avoid asking for unnecessary values.
- Source operations are designed to be simple and responsive.

### Cloudflare Scanner Performance

- **100 workers**: Scans ~1000 IPs per second.
- **Configurable workers**: Increase for faster scans.
- **Real-time updates**: Results appear instantly.
- **Live saving**: No data loss if interrupted.
- **Smart timeout handling**: Configurable per-port timeouts.

### Config Testing Performance (New in 1.5.1)

- Each config test includes TLS/WebSocket handshake
- Tests are slower than basic HTTP probes but provide real validation
- Use `-config-test-timeout` to adjust for slower edges
- Stop early with `-stop-after` when you have enough working configs

***

## Troubleshooting

### Build issues

If `go build` fails:
- Make sure `VERSION` is declared as a string.
- Make sure config structs match the fields used in the code.
- Remove unused variables or wire them into the config properly.
- Check for duplicate prompts or mismatched prompt logic.

### Interactive issues

If the menu feels broken:
- Make sure the terminal supports ANSI colors.
- Check that the cursor is restored on exit.
- Use arrow keys or numeric selection as supported by the UI.

### Update issues

If update fails:
- Confirm Go is installed.
- Confirm Git is installed.
- On Windows, ensure release downloads are allowed.
- If all else fails, use the source clone/build path manually.

### Scraper issues

If source actions do not work:
- Confirm the source URL is valid.
- Confirm the config reloads successfully.
- Use `show-config` to verify what is currently active.

### Cloudflare Scanner issues

If scanner fails:
- Increase timeout values: `-timeout 10 -port-timeout 5`
- Reduce workers: `-workers 50`
- Check network connectivity.
- Use custom ranges for targeted scanning.

### Config Testing issues (New in 1.5.1)

If config tests fail:
- Increase config test timeout: `-config-test-timeout 15`
- Check if the config format is correct (VMess, VLESS, Trojan, SS)
- Try with `-no-auto-subnet` if auto-subnet is causing issues
- Use `-ports` to ensure the config's port is scanned
- Check if the config's domain resolves correctly

***

## Project Structure

```txt
ct/
├── main.go
├── go.mod
├── go.sum
├── pc/
├── mtp/
├── xp/
├── scraper/
├── cf/              # Cloudflare scanner module
├── output/
```

***

## Changelog

### 1.5.1

- **Added Proxy Configuration Testing** — Test real VMess, VLESS, Trojan, and SS configs.
- Added smart source selection with auto-domain detection.
- Added auto-subnet fallback for config IPs.
- Added automatic port addition from configs.
- Added two-pass scanning (Cloudflare ranges → config subnet).
- Added config test output files: `config_tested_ips_*.txt` and `config_tested_success_*.txt`.
- Added `ConfigTested`, `ConfigTestOK`, `ConfigTestError`, `ConfigTestMs`, `ConfigFinalURI` fields to results.
- Added `Cfg` column to live display.
- Added `-config`, `-config-test-timeout`, `-no-auto-subnet`, `-subnet-prefix` flags.
- Added WebSocket upgrade handshake support.
- Added subscription list expansion support.
- Added base64 config decoding support.
- Improved `-stop-after` logic for config testing.
- Improved config parsing for all supported formats.
- Improved error handling and reporting for config tests.
- Fixed `-stop-after` to work correctly with config tests.

### 1.4.15

- **Added Cloudflare IP Scanner module** — Complete IP scanning solution.
- Added real-time scanning with live table updates.
- Added automatic Cloudflare validation.
- Added HTTP/2 and HTTP/3 detection.
- Added latency measurement with color coding.
- Added real-time IP saving to `valid_ips_*.txt`.
- Added multiple output formats (JSON, CSV, TXT).
- Added custom range and IP file support.
- Added optional GeoIP and speed test features.
- Added interactive menu integration.
- Added comprehensive command-line flags.
- Improved color-coded terminal output.
- Improved progress tracking with ETA.

### 1.3.12

- Added improved interactive menu UX.
- Added numeric support for menu selection.
- Added conditional prompts in modules.
- Added scraper source management menu.
- Added `scrape run` direct execution.
- Added built-in update checker.
- Added multi-path update fallback.
- Improved defaults and prompt logic.
- Improved source management workflow.
- Improved overall usability.

### 1.3.9

- Stable CLI improvements.
- Existing module support and testing workflow.

***

## License

MIT License.

## Support

- GitHub: [BatmanPriv](https://github.com/batmanpriv)
- Repository: [CT](https://github.com/batmanpriv/ct)

***

*CT — Check Test*
