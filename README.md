# CT - Check Test

**Version: 1.3.9**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/batmanpriv/CheckTest)

## Overview

**CT** is a powerful, multi-purpose network diagnostic and optimization tool written in Go. It combines a high-performance DNS benchmark, a feature-rich proxy checker, an MTProto proxy tester, and a comprehensive Xray/V2Ray config tester—all in a single executable.

### Why CT?

- **All-in-One Solution** — DNS benchmarking, proxy checking, MTProto testing, and Xray config testing
- **Production-Ready** — Battle-tested with thousands of DNS servers, proxies, and configs
- **Cross-Platform** — Windows, Linux, and macOS support with native system integration
- **Performance-First** — Concurrent architecture maximizes throughput while minimizing resource usage

***

# ScreenShot

<img src="https://github.com/user-attachments/assets/0413df28-3e25-4d35-b03b-df09fbcede0c">

## What's New in 1.3.8

### 🚨 New: MTProto Proxy Checker (Beta)

> ⚠️ **Note:** This module is experimental and may not be 100% reliable. Use with caution.

- **MTProto Protocol Support** — Test Telegram MTProto proxies
- **Multiple Input Formats** — Supports `t.me/proxy`, `tg://proxy`, and raw formats
- **Real-time Health Check** — Validates proxies with actual TCP connection
- **Latency Measurement** — Reports response time for each proxy
- **Auto-Download** — Fetches proxies from public MTProto sources
- **File Output** — Saves healthy proxies to `valid_mtproto.txt`
- **Concurrent Testing** — Multi-threaded testing for speed

### 🛠️ MTProto Usage

```bash
# Test MTProto proxies from a file
ct -mtproto proxies.txt

# Download and test from public sources
ct -mtproto-dl

# Custom threads and timeout
ct -mtproto proxies.txt -mtproto-t 20 -mtproto-timeout 2

# Custom output file
ct -mtproto proxies.txt -mtproto-out healthy.txt

# Disable colored output
ct -mtproto proxies.txt -mtproto-no-color
```

### 🕷️ Proxy Scraper Module (New in 1.3.8!)

- **Multi-Source Scraping** — Scrapes proxies and configs from 50+ public sources
- **Telegram Channel Support** — Extracts from public Telegram channels (requires VPN/proxy)
- **Protocol Detection** — Auto-detects VLESS, VMESS, Trojan, SS, MTProto, HTTP/SOCKS
- **Config Extraction** — Parses and extracts proxy configs from raw text
- **Concurrent Scraping** — Multi-threaded scraping for maximum speed
- **Deduplication** — Automatically removes duplicate entries
- **Country-Based Output** — Saves configs to separate files by protocol type
- **Custom Source Management** — Add your own scraping sources

#### Supported Sources

- **Config Lists** — GitHub, GitLab, Pastebin, raw URLs (20+ pre-configured)
- **MTProto Lists** — Public MTProto proxy lists
- **Proxy Lists** — HTTP, HTTPS, SOCKS4, SOCKS5 from multiple sources
- **Telegram Channels** — Public proxy/config channels (requires VPN)

#### Scraper Usage

```bash
# Scrape all sources (default)
ct -scrape-only

# Skip Telegram scraping
ct -scrape-only -skip-telegram

# Custom output directory
ct -scrape-only -output scraped_configs

# Custom worker threads
ct -scrape-only -workers 20

# Add custom source
ct -source https://example.com/configs.txt

# Add custom Telegram channel
ct -source https://t.me/mychannel telegram

# View current sources
ct -show-config

# Reload default sources (reset config)
ct -reload

# Remove a source
ct -remove-url https://example.com/old-list.txt
```

#### Output Files

After scraping, configs are saved to the `output/` directory:

```
output/
├── vless.txt      # VLESS configs
├── vmess.txt      # VMESS configs
├── trojan.txt     # Trojan configs
├── ss.txt         # ShadowSocks configs
├── mtproto.txt    # MTProto proxies (tg:// links)
├── http.txt       # HTTP proxies
├── https.txt      # HTTPS proxies
├── socks4.txt     # SOCKS4 proxies
└── socks5.txt     # SOCKS5 proxies
```

#### Example Output

```
╔════════════════════════════════════════╗
║     Proxy Scraper - Starting...      ║
╚════════════════════════════════════════╝

[ℹ] Workers: 10
[ℹ] Config URLs: 25
[ℹ] MTProto URLs: 10
[ℹ] Proxy Types: 5
[ℹ] Telegram Channels: 7
[ℹ] Custom Sources: 3

[Worker 1] Scraping config: https://raw.githubusercontent.com/...
[Worker 2] Scraping mtproto: https://raw.githubusercontent.com/...
[Worker 3] Scraping telegram: https://t.me/ProxyMTProto
[Worker 1] [✓] Success: https://raw.githubusercontent.com/... (vless:45 vmess:23 trojan:12 ss:8 mtproto:0 proxy:15)
[Worker 3] [✓] Success: https://t.me/ProxyMTProto (vless:12 vmess:8 trojan:5 ss:3 mtproto:25 proxy:0)
[Progress] 15/47 (31.9%)

[✓] Saved 234 items to output/vless.txt
[✓] Saved 156 items to output/vmess.txt
[✓] Saved 89 items to output/trojan.txt
[✓] Saved 67 items to output/ss.txt
[✓] Saved 145 items to output/mtproto.txt
[✓] Saved 78 items to output/http.txt
[✓] Saved 92 items to output/socks5.txt
```

#### Scraper Configuration

The scraper uses a `sources.json` config file stored in:
- **Windows:** `C:\Users\<username>\.proxy-scraper\sources.json`
- **Linux/macOS:** `~/.proxy-scraper/sources.json`

This file contains:
- Config URLs (VLESS, VMESS, Trojan, SS)
- MTProto URLs
- Proxy list URLs (HTTP, HTTPS, SOCKS)
- Telegram channel URLs
- Custom sources

### 🚀 Xray Config Checker Improvements

- Automatically saves alive configs into country-based files
- Added **custom HTTP test URL** (`-xray-url`)
- HTTP status code reporting
- Better latency measurement
- Improved Xray startup detection
- Automatic SOCKS5 readiness verification
- Better config deduplication
- Improved GeoIP caching
- Automatic GeoIP API fallback
- More stable HTTP validation
- Better error reporting from Xray
- Improved Reality/TLS handling
- Added support for additional transport types:
  - WebSocket
  - gRPC
  - XHTTP
  - HTTPUpgrade
- Better VMess parser
- Better Shadowsocks parser
- Improved IPv6 support
- Automatic region directory creation
- Alive configs can now be exported by country

### 🛠 Bug Fixes

- Fixed random Xray startup failures
- Fixed VMess parsing edge cases
- Fixed Shadowsocks parsing issues
- Fixed duplicated config handling
- Fixed HTTP timeout handling
- Fixed SOCKS5 connection race conditions
- Fixed Reality configuration generation
- Fixed TLS fingerprint parsing
- Fixed ALPN parsing
- Fixed GeoIP cache synchronization
- Fixed temporary config cleanup
- Improved concurrent testing stability

***

## Features

### 🔍 DNS Benchmark Module

- **Multi-Domain Testing** — Test against multiple domains simultaneously
- **Complete Protocol Support** — UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH)
- **Comprehensive Validation** — DNSSEC, EDNS, IPv6 support detection
- **HTTP Verification** — Validate DNS responses by checking HTTPS connectivity
- **Geolocation** — Country and ISP identification for each DNS server
- **Scoring System** — Intelligent scoring based on speed, reliability, and features
- **Batch Processing** — Test thousands of DNS servers with configurable concurrency

### 🚀 Proxy Checker Module

- **Multi-Protocol Support** — HTTP, HTTPS, SOCKS4, SOCKS5
- **Authentication Support** — Username/password authentication for all protocols
- **Anonymity Detection** — Identifies elite, anonymous, and transparent proxies
- **Performance Metrics** — Latency, speed classification, and comprehensive scoring
- **GeoIP Integration** — Country and provider identification
- **Proxy Scraping** — Download or scrape proxies from various sources
- **IPv6 Support** — Full IPv6 proxy detection and testing

### 🔶 MTProto Proxy Checker (Beta)

- **Telegram Proxy Support** — Test MTProto proxies for Telegram
- **Multiple Formats** — `t.me/proxy`, `tg://proxy`, key=value, and raw formats
- **TCP Health Check** — Validates connection with actual TCP handshake
- **Secret Decoding** — Handles hex-encoded secrets (0x, dd/ee prefix)
- **Real-time Results** — Shows OK/BAD status with latency
- **Auto-Save** — Writes healthy proxies to file in real-time
- **Multi-Source Download** — Fetches from GitHub public lists

> ⚠️ **Experimental:** This module is under active development and may not work reliably in all cases.

### 🛸 Xray Config Checker Module

- **Protocol Support** — VLESS, VMESS, Trojan, ShadowSocks
- **Transport Types** — TCP, WS (WebSocket), gRPC, XHTTP, HTTPUpgrade
- **Security Types** — TLS, Reality, None
- **Config Sources** — 20+ public config sources pre-configured
- **Automatic Binary** — Downloads Xray core binary on first run
- **Live Testing** — Validates configs by actually connecting through proxy
- **HTTP Test** — Optional HTTP request test for 100% validation
- **Location Detection** — Country, city, and ISP for each server
- **Config Deduplication** — Automatically removes duplicate configs
- **Smart Caching** — Caches GeoIP data to prevent rate limiting
- **Multi-API Fallback** — Uses ip-api.com, ipinfo.io with automatic fallback

### ⚡ System Integration

- **Automatic Configuration** — Apply best DNS, proxy, or Xray config to your system
- **Cross-Platform System Settings** — Native support for Windows, Linux, macOS
- **Status Reporting** — View current system DNS and proxy settings

***

## Installation

### Using Go Install (Recommended)

```bash
go install github.com/batmanpriv/ct@1.3.9
```

This will install the `ct` binary to your `$GOPATH/bin` directory.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/batmanpriv/ct.git
cd ct

# Build the binary
go build -o ct main.go

# Or install locally
go install
```

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/batmanpriv/ct/releases).

***

## Quick Start Guide

### DNS Benchmarking

```bash
# Test DNS servers from a file
ct -dns resolvers.txt

# Test with HTTP verification
ct -dns resolvers.txt -mode 1

# Test specific domains
ct -dns resolvers.txt -domains "google.com,github.com,cloudflare.com"

# Use more threads for faster testing
ct -dns resolvers.txt -t 50

# Score-based sorting (recommended)
ct -dns resolvers.txt -mode 1 -score

# Find and apply the best DNS server
ct -apply-best

# Check current DNS settings
ct -set status
```

### Proxy Checking

```bash
# Check proxies from a file
ct -proxy proxies.txt

# Specify proxy types to test
ct -proxy proxies.txt -proxy-types socks5

# Auto-detect proxy types (slower but more accurate)
ct -proxy proxies.txt -proxy-auto

# More threads for faster checking
ct -proxy proxies.txt -proxy-t 100

# Score-based sorting
ct -proxy proxies.txt -proxy-score

# Download fresh proxies
ct -proxy-dl

# Find and apply the best proxy
ct -proxy-apply-best

# Check current proxy settings
ct -proxy-set status
```

### MTProto Proxy Testing (Beta)

```bash
# Test MTProto proxies from a file
ct -mtproto mtproto.txt

# Download from public sources and test
ct -mtproto-dl

# Custom threads and timeout
ct -mtproto mtproto.txt -mtproto-t 20 -mtproto-timeout 2

# Custom output file
ct -mtproto mtproto.txt -mtproto-out healthy_mtproto.txt

# Disable colored output
ct -mtproto mtproto.txt -mtproto-no-color
```

### Xray Config Testing

```bash
# Test configs from a file
ct -xray-file configs.txt

# Download and test configs from online sources
ct -xray-dl

# Limit to 100 configs
ct -xray-dl -xray-limit 100

# Custom threads and timeout
ct -xray-file configs.txt -xray-threads 20 -xray-timeout 1

# Add a custom source
ct -xray-add-source https://example.com/configs.txt

# Output to custom file
ct -xray-file configs.txt -xray-output alive.txt

# Custom HTTP test URL
ct -xray-file configs.txt -xray-url https://google.com
```

***

## Command Reference

### DNS Module Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-dns` | Path to DNS server list file | `-` |
| `-t` | Number of concurrent threads | `10` |
| `-domains` | Comma-separated domains to test | `cloudflare.com` |
| `-url` | Single URL to test (overrides -domains) | `-` |
| `-mode` | Test mode: `0` (DNS only), `1` (DNS + HTTP) | `0` |
| `-json` | Export results in JSON format | `false` |
| `-score` | Sort by score instead of speed | `false` |
| `-no-color` | Disable colored output | `false` |
| `-set` | Set system DNS or check status | `-` |
| `-apply-best` | Find best DNS and apply to system | `false` |
| `-insecure` | Allow insecure TLS for DoT | `false` |

### Proxy Module Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-proxy` | Path to proxy list file | `-` |
| `-proxy-t` | Number of concurrent threads | `50` |
| `-proxy-types` | Comma-separated proxy types to test | `-` |
| `-proxy-auto` | Auto-detect proxy type | `true` |
| `-proxy-dl` | Download proxies from public sources | `false` |
| `-proxy-scrape` | Scrape proxies from URL | `false` |
| `-proxy-score` | Sort by score instead of speed | `false` |
| `-proxy-apply-best` | Find best proxy and apply to system | `false` |
| `-proxy-set` | Set system proxy or check status | `-` |
| `-proxy-url` | Test URL for proxy checking | `https://telegram.org` |

### MTProto Module Flags (Beta)

| Flag | Description | Default |
|------|-------------|---------|
| `-mtproto` | Path to MTProto proxy list file | `-` |
| `-mtproto-dl` | Download proxies from public sources | `false` |
| `-mtproto-t` | Number of concurrent threads | `20` |
| `-mtproto-timeout` | Timeout in seconds for each test | `2` |
| `-mtproto-out` | Output file for healthy proxies | `valid_mtproto.txt` |
| `-mtproto-no-color` | Disable colored output | `false` |

### Xray Config Module Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-xray-file` | Path to Xray config file | `-` |
| `-xray-dl` | Download configs from online sources | `false` |
| `-xray-limit` | Limit number of configs to test | `0` (no limit) |
| `-xray-threads` | Number of concurrent threads | `10` |
| `-xray-timeout` | Test timeout in seconds | `0.5` |
| `-xray-add-source` | Add new config source URL | `-` |
| `-xray-output` | Output file for alive configs | `alive_configs.txt` |
| `-xray-url` | Custom HTTP test URL | `https://google.com` |

### Scraper Module Flags (New in 1.3.8!)

| Flag | Description | Default |
|------|-------------|---------|
| `-scrape-only` | Scrape all sources | `false` |
| `-skip-telegram` | Skip Telegram scraping | `false` |
| `-output` | Output directory for scraped configs | `output` |
| `-workers` | Number of concurrent workers | `10` |
| `-source` | Add new scraping source URL | `-` |
| `-show-config` | Show current sources config | `false` |
| `-reload` | Reload/reset config to defaults | `false` |
| `-remove-url` | Remove a source from config | `-` |

***

## Input File Formats

### DNS Server List

One DNS server per line. Supports:

```
# Comment lines start with #
1.1.1.1:53
8.8.8.8
[2001:4860:4860::8888]:53
9.9.9.9
```

### Proxy List

One proxy per line. Supports various formats:

```
# HTTP/HTTPS proxies
http://user:pass@192.168.1.1:8080
https://192.168.1.2:443

# SOCKS proxies
socks5://user:pass@192.168.1.3:1080
socks4://192.168.1.4:1081

# Plain format (auto-detected)
192.168.1.5:8080
192.168.1.6:1080
```

### MTProto Proxy List

One proxy per line. Supports multiple formats:

```
# t.me/proxy links
https://t.me/proxy?server=example.com&port=443&secret=hexsecret

# tg:// links
tg://proxy?server=example.com&port=443&secret=hexsecret

# Key=value format
server=example.com port=443 secret=hexsecret

# Raw format
example.com 443 hexsecret
```

### Xray Config List

One config link per line. Supports VLESS, VMESS, Trojan, SS:

```
vless://uuid@server:port?security=tls&type=ws&path=/path&host=domain.com
vmess://base64_encoded_config
trojan://password@server:port?security=tls&type=ws&sni=domain.com
ss://method:password@server:port
```

***

## Output Examples

### DNS Benchmark Output

```
DNS Benchmark - Testing 1000 servers

Progress: 100.0% (1000/1000) | Valid: 847

#    DNS              Lookup      HTTPS        Location   Provider             Score
-------------------------------------------------------------------------------------
#1   1.1.1.1          8ms         45ms         US         Cloudflare           95
#2   8.8.8.8          12ms        52ms         US         Google               92
#3   9.9.9.9          15ms        58ms         US         Quad9                88

========================================
Total DNS Tested: 847
Valid DNS (Lookup OK): 847
HTTPS OK: 813
Average Score: 67/100
Fastest DNS: 1.1.1.1 (8ms)
Highest Score: 1.1.1.1 (95/100)
========================================
```

### MTProto Proxy Output

```
[i] starting download
[i] sources:
  - https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt
  - https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt
[i] checking 250 proxies with 20 threads and 2s timeout
[OK] 185.143.230.10:443 | 145ms
[BAD] 104.21.94.161:443 | context deadline exceeded
[OK] 93.152.205.216:443 | 162ms

OK: 87 | BAD: 163 | TOTAL: 250
```

### Xray Config Output

```
Downloading configs from online sources...
Downloaded 245 configs from https://raw.githubusercontent.com/...
Loaded 245 configs
Xray binary already exists
Using xray binary: C:\Users\...\.xray-test\xray.exe
Threads: 10, Timeout: 0.5s

Testing configs...

[0] ✓ ALIVE 173.245.58.75(vless) 1630ms [United States - San Francisco - Cloudflare]
[1] ✓ ALIVE 93.152.205.216(vless) 1630ms [Netherlands - Amsterdam - Serverius]
[2] ✗ DEAD 104.21.94.161: not responding
[3] ✓ ALIVE 162.159.38.119(vless) 2100ms [United States - San Francisco - Cloudflare]

=== SUMMARY ===
Total: 245
Alive: 78
Dead: 167

=== LOCATION STATS ===
United States: 45
Netherlands: 12
Germany: 8
France: 6
United Kingdom: 4
Canada: 3

Alive configs saved to: alive_configs.txt
```

***

## Xray Config Sources

The tool automatically downloads from these sources:

1. ebrasha/free-v2ray-public-list (vless, vmess, trojan, ss)
2. Epodonios/v2ray-configs
3. roosterkid/openproxylist
4. miladtahanian/V2RayCFGDumper
5. barry-far/V2ray-config (Sub1-8)
6. barry-far/V2ray-config (Splitted-By-Protocol)

### Adding Custom Sources

```bash
# Add a single source
ct -xray-add-source https://example.com/my-configs.txt

# Sources are saved to sources.json for future use
```

***

## Advanced Usage

### DNS + HTTP Verification

Mode 1 performs HTTP verification using the resolved IP:

```bash
ct -dns resolvers.txt -mode 1 -domains "google.com,github.com"
```

### Xray HTTP Verification

Tests configs by actually making HTTP requests through the proxy:

```bash
ct -xray-file configs.txt -xray-url https://www.google.com
```

This validates that the config works by:
1. Starting Xray with the config
2. Connecting through the proxy
3. Making an HTTP request
4. Verifying the response

### Scoring System

The scoring algorithm evaluates:

**DNS Component (40 points max):**
- Successful resolution: 20 points
- Speed tiers: <10ms (+15), <50ms (+10), <100ms (+5)

**HTTP Component (35 points max):**
- HTTPS support: 20 points
- Speed tiers: <50ms (+15), <200ms (+10), <500ms (+5)

**Features (25 points max):**
- DNSSEC: 10 points
- EDNS: 5 points
- IPv6: 5 points
- UDP & TCP support: 5 points
- DoT/DoH: 5 points

### Automated System Configuration

Apply the best DNS server automatically:

```bash
# Windows (requires Administrator)
ct -apply-best

# Linux
sudo ct -apply-best

# macOS
sudo ct -apply-best
```

The tool automatically detects your OS and applies the recommended settings.

***

## Performance Optimization

### Thread Management

- **DNS Testing:** Use `-t` flag (default: 10)
  - Higher threads reduce total testing time
  - Recommended: 50-100 for large DNS lists

- **Proxy Testing:** Use `-proxy-t` flag (default: 50)
  - Higher threads significantly speed up testing
  - Recommended: 100-200 for thousands of proxies

- **MTProto Testing:** Use `-mtproto-t` flag (default: 20)
  - Each test opens a TCP connection
  - Recommended: 20-50 depending on network

- **Xray Testing:** Use `-xray-threads` flag (default: 10)
  - Each test starts a new Xray instance
  - Recommended: 5-20 depending on system resources

### Memory Considerations

- Results are stored in memory during testing
- For very large lists, use `-xray-limit` to limit testing

***

## Troubleshooting

### Common Issues

**"Error opening file: The system cannot find the file specified"**
- Verify the file path is correct
- Use absolute paths or proper relative paths

**"Xray binary not found"**
- The tool automatically downloads Xray on first run
- Ensure you have internet connection
- Check antivirus isn't blocking the download

**"Failed to set DNS/Proxy (Permission denied)"**
- Run with administrator/root privileges
- On Windows: Right-click → Run as Administrator
- On Linux/macOS: Use `sudo`

**"GeoIP API rate limited"**
- The tool automatically falls back to alternative APIs
- Location data is cached to minimize API calls
- Use `-xray-limit` to reduce testing volume

**"MTProto test not working reliably"**
- This module is experimental (beta)
- Some proxies may timeout or fail unexpectedly
- Try increasing `-mtproto-timeout` for better results

***

## Project Structure

```
ct/
├── main.go                    # Main entry point with DNS benchmark
├── go.mod                     # Go module definition
├── go.sum                     # Dependency checksums
├── pc/
│   └── proxy-checker.go       # Proxy checker module
├── mtp/
│   └── mtproto-checker.go     # MTProto proxy checker (Beta!)
├── xp/
│   └── xray-checker.go        # Xray config checker module
└── resolvers.txt              # DNS server list
```

### Dependencies

- [`golang.org/x/net/proxy`](https://pkg.go.dev/golang.org/x/net/proxy) — SOCKS proxy support
- [`github.com/miekg/dns`](https://pkg.go.dev/github.com/miekg/dns) — DNS protocol implementation

***

## Changelog

### 1.3.8 (2026)
- **NEW:** MTProto proxy checker module (beta/experimental)
- Multi-format MTProto parsing (t.me/proxy, tg://proxy, raw)
- TCP health check with latency measurement
- Real-time result output
- Auto-save healthy proxies to file
- Added Xray/V2Ray config checker module
- Multi-protocol support: VLESS, VMESS, Trojan, SS
- Automatic Xray binary download
- Config scraping from 20+ public sources
- Custom source management
- GeoIP detection with multi-API fallback
- HTTP verification for 100% config validation

### 1.0.2
- Added proxy checker module
- Multi-protocol proxy support
- Proxy scraping and downloading
- System proxy configuration

### 1.0.0
- Initial DNS benchmark release
- DNS-over-TLS and DNS-over-HTTPS support
- System DNS configuration

***

### Development Setup

```bash
# Clone and enter directory
git clone https://github.com/batmanpriv/ct.git
cd ct

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o ct main.go
```

***

## License

MIT License — See [LICENSE](LICENSE) file for details.

## Support

- **Issues:** [GitHub Issues](https://github.com/batmanpriv/ct/issues)
- **Discussions:** [GitHub Discussions](https://github.com/batmanpriv/ct/discussions)


*CT — The Complete Network Testing Tool*

***
