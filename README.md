# CT - Check Test

**Version: 1.2.5**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/batmanpriv/CheckTest)

## Overview

**CT** is a powerful, multi-purpose network diagnostic and optimization tool written in Go. It combines a high-performance DNS benchmark, a feature-rich proxy checker, and a comprehensive Xray/V2Ray config tester—all in a single executable.

### Why CT?

- **All-in-One Solution** — DNS benchmarking, proxy checking, and Xray config testing
- **Production-Ready** — Battle-tested with thousands of DNS servers, proxies, and configs
- **Cross-Platform** — Windows, Linux, and macOS support with native system integration
- **Performance-First** — Concurrent architecture maximizes throughput while minimizing resource usage

---

# ScreenShot

<img src="https://github.com/user-attachments/assets/816beda5-bbd9-451b-90a8-2c4e8fca6b3a">

## What's New in 1.2.5

### 🚀 Xray Config Checker Improvements

- Added **Region Sorting** (`-xray-region-sort`)
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

---

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

### 🛸 Xray Config Checker Module (New!)

- **Protocol Support** — VLESS, VMESS, Trojan, ShadowSocks
- **Transport Types** — TCP, WS (WebSocket), gRPC
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

---

## Installation

### Using Go Install (Recommended)

```bash
go install github.com/batmanpriv/ct@1.2.5
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

---

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

### Xray Config Testing (New!)

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

```

---

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

### Xray Config Module Flags (New!)

| Flag | Description | Default |
|------|-------------|---------|
| `-xray-file` | Path to Xray config file | `-` |
| `-xray-dl` | Download configs from online sources | `false` |
| `-xray-limit` | Limit number of configs to test | `0` (no limit) |
| `-xray-threads` | Number of concurrent threads | `10` |
| `-xray-timeout` | Test timeout in seconds | `0.5` |
| `-xray-add-source` | Add new config source URL | `-` |
| `-xray-output` | Output file for alive configs | `alive_configs.txt` |
| `-xray-url` | Send Request with config to url | `https://google.com` |

---

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

### Xray Config List

One config link per line. Supports VLESS, VMESS, Trojan, SS:

```
vless://uuid@server:port?security=tls&type=ws&path=/path&host=domain.com
vmess://base64_encoded_config
trojan://password@server:port?security=tls&type=ws&sni=domain.com
ss://method:password@server:port
```

---

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

### Xray Config Output

```
Downloading configs from online sources...
Downloaded 245 configs from https://raw.githubusercontent.com/...
Loaded 245 configs
Xray binary already exists
Using xray binary: C:\Users\\.xray-test\xray.exe
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

---

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

---

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

---

## Performance Optimization

### Thread Management

- **DNS Testing:** Use `-t` flag (default: 10)
  - Higher threads reduce total testing time
  - Recommended: 50-100 for large DNS lists

- **Proxy Testing:** Use `-proxy-t` flag (default: 50)
  - Higher threads significantly speed up testing
  - Recommended: 100-200 for thousands of proxies

- **Xray Testing:** Use `-xray-threads` flag (default: 10)
  - Each test starts a new Xray instance
  - Recommended: 5-20 depending on system resources

### Memory Considerations

- Results are stored in memory during testing
- For very large lists, use `-xray-limit` to limit testing

---

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

---

## Project Structure

```
ct/
├── main.go                    # Main entry point with DNS benchmark
├── go.mod                     # Go module definition
├── go.sum                     # Dependency checksums
├── pc/
│   └── proxy-checker.go       # Proxy checker module
├── xp/
│   └── xray-checker.go        # Xray config checker module (New!)
└── resolvers.txt              # DNS server list
```

### Dependencies

- [`golang.org/x/net/proxy`](https://pkg.go.dev/golang.org/x/net/proxy) — SOCKS proxy support
- [`github.com/miekg/dns`](https://pkg.go.dev/github.com/miekg/dns) — DNS protocol implementation

---

## Changelog

### 1.2.5 (2024)
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

---

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

---

## License

MIT License — See [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- DNS protocol support by [miekg/dns](https://github.com/miekg/dns)
- Proxy support by [golang.org/x/net](https://pkg.go.dev/golang.org/x/net)
- Xray core by [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- GeoIP data from [ip-api.com](https://ip-api.com) and [ipinfo.io](https://ipinfo.io)
- Public config lists from various open-source projects

---

## Support

- **Issues:** [GitHub Issues](https://github.com/batmanpriv/ct/issues)
- **Discussions:** [GitHub Discussions](https://github.com/batmanpriv/ct/discussions)

---

*CT — The Complete Network Testing Tool*
