# CT - Comprehensive Network Testing Tool

**Version: 1.0.2**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/batmanpriv/CheckTest)

## Overview

**CT** is a powerful, dual-purpose network diagnostic and optimization tool written in Go. It combines a high-performance DNS benchmark with a feature-rich proxy checker, delivering professional-grade network analysis in a single executable.

### Why CT?

- **All-in-One Solution** — No need for separate DNS benchmarking and proxy checking tools
- **Production-Ready** — Battle-tested with thousands of DNS servers and proxies
- **Cross-Platform** — Windows, Linux, and macOS support with native system integration
- **Performance-First** — Concurrent architecture maximizes throughput while minimizing resource usage

---

# ScreenShot

<img src="https://github.com/user-attachments/assets/816beda5-bbd9-451b-90a8-2c4e8fca6b3a">

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

### ⚡ System Integration

- **Automatic Configuration** — Apply best DNS or proxy to your system with one command
- **Cross-Platform System Settings** — Native support for Windows, Linux, macOS
- **Status Reporting** — View current system DNS and proxy settings

---

## Installation

### Using Go Install (Recommended)

```bash
go install github.com/batmanpriv/ct@1.0.2
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

# Download specific proxy types
ct -proxy-dl -proxy-type socks5

# Scrape proxies from URL
ct -proxy-scrape https://example.com/proxies.txt

# Deep scraping (recursive)
ct -proxy-scrape-deep https://example.com/proxies.txt

# Find and apply the best proxy
ct -proxy-apply-best

# Check current proxy settings
ct -proxy-set status
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
| `-proxy-type` | Proxy type to download (`all`, `socks5`, etc.) | `all` |
| `-proxy-scrape` | Scrape proxies from URL | `false` |
| `-proxy-scrape-deep` | Deep recursive scraping | `false` |
| `-proxy-score` | Sort by score instead of speed | `false` |
| `-proxy-apply-best` | Find best proxy and apply to system | `false` |
| `-proxy-set` | Set system proxy or check status | `-` |
| `-proxy-url` | Test URL for proxy checking | `https://telegram.org` |

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
#4   94.140.14.14     22ms        65ms         NL         AdGuard              85
#5   208.67.222.222   25ms        70ms         US         Cisco                82

========================================
Total DNS Tested: 847
Valid DNS (Lookup OK): 847
HTTPS OK: 813
Average Score: 67/100
Fastest DNS: 1.1.1.1 (8ms)
Highest Score: 1.1.1.1 (95/100)
========================================

========================================
      RECOMMENDED DNS CONFIGURATION
========================================

Primary:   1.1.1.1
Secondary: 8.8.8.8

Reason:
  • Latency: 8ms (Excellent)
  • HTTPS: 45ms
  • DNSSEC: true
  • DoH: true
  • IPv6: true
  • Score: 95/100
```

### Proxy Checker Output

```
Proxy Checker - Testing 5000 proxies

Progress: 100.0% (5000/5000) | Working: 234

#    Proxy                Type      Latency    Country      Anonymity   Speed    Score  IPv6  Auth
----------------------------------------------------------------------------------------------------
#1   socks5://1.2.3.4      socks5    45ms       US           elite       fast     85     ✅    ❌
#2   https://5.6.7.8       https     52ms       DE           anonymous   fast     78     ❌    ✅
#3   http://9.10.11.12     http      65ms       GB           transparent medium   62     ❌    ❌
#4   socks4://13.14.15.16  socks4    78ms       CA           elite       medium   58     ❌    ❌
#5   socks5://17.18.19.20  socks5    95ms       AU           anonymous   slow     45     ✅    ✅

========================================
Total Proxies in File: 5000
Working Proxies: 234
Success Rate: 4.7%
Average Latency: 67ms
Average Score: 61/100
Best Proxy: socks5://1.2.3.4 (45ms)
========================================

========================================
      RECOMMENDED PROXY CONFIGURATION
========================================

Primary:   socks5://1.2.3.4

Reason:
  • Type: socks5
  • Latency: 45ms
  • Anonymity: elite
  • Speed: fast
  • IPv6: true
  • Auth: false
  • Score: 85/100
========================================
```

---

## Advanced Usage

### DNS + HTTP Verification

Mode 1 performs HTTP verification using the resolved IP:

```bash
ct -dns resolvers.txt -mode 1 -domains "google.com,github.com"
```

This validates that the DNS server provides correct IP resolution by:
1. Performing DNS lookup for the domain
2. Establishing HTTPS connection to the resolved IP
3. Verifying TLS certificate and HTTP response

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
- Additional record types: 2 points each

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

The tool automatically detects your OS and applies the recommended settings using:
- Windows: `netsh` + PowerShell
- Linux: `systemd-resolved` or `/etc/resolv.conf`
- macOS: `networksetup`

---

## Performance Optimization

### Thread Management

- **DNS Testing:** Use `-t` flag (default: 10)
  - Higher threads reduce total testing time
  - Recommended: 50-100 for large DNS lists

- **Proxy Testing:** Use `-proxy-t` flag (default: 50)
  - Higher threads significantly speed up testing
  - Recommended: 100-200 for thousands of proxies

### Memory Considerations

- Results are stored in memory during testing
- For very large lists (>50,000 items), consider:
  - Using the `-json` flag to save results incrementally
  - Filtering input lists before testing

### Network Configuration

- Ensure stable network connection during testing
- DNS-over-HTTPS and DoT require proper TLS configuration
- Use `-insecure` flag for testing with self-signed certificates

---

## Troubleshooting

### Common Issues

**"Error opening file: The system cannot find the file specified"**
- Verify the file path is correct
- Use absolute paths or proper relative paths

**"No valid proxies found"**
- Check proxy format in the input file
- Ensure proxies are accessible from your network
- Increase timeout with proxy-specific flags

**"Failed to set DNS/Proxy (Permission denied)"**
- Run with administrator/root privileges
- On Windows: Right-click → Run as Administrator
- On Linux/macOS: Use `sudo`

**Slow testing performance**
- Increase thread count with `-t` or `-proxy-t`
- Reduce timeout values
- Test smaller batches

### DNS Server Format Issues

The tool automatically handles:
- Missing port (defaults to 53)
- IPv6 addresses with and without brackets
- Comments starting with `#`
- Whitespace and special characters

---

## Project Structure

```
ct/
├── main.go                    # Main entry point with DNS benchmark
├── go.mod                     # Go module definition
├── go.sum                     # Dependency checksums
├── resolvers.txt              # DNS server list (7,886 servers)
└── pc/
    └── proxy-checker.go       # Proxy checker module
```

### Dependencies

- [`golang.org/x/net/proxy`](https://pkg.go.dev/golang.org/x/net/proxy) — SOCKS proxy support
- [`github.com/miekg/dns`](https://pkg.go.dev/github.com/miekg/dns) — DNS protocol implementation

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

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
- Public proxy and DNS lists from various open-source projects

---

## Support

- **Issues:** [GitHub Issues](https://github.com/batmanpriv/ct/issues)
- **Discussions:** [GitHub Discussions](https://github.com/batmanpriv/ct/discussions)

---

*CT — The Complete Network Testing Tool*
