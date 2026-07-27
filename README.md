<h1 align="center"> CT - Check Test</h1>

<p align="center">
Version: 1.3.12

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/batmanpriv/CheckTest)

**CT** is a fast, flexible, multi-purpose network testing suite written in Go. It brings together DNS benchmarking, proxy checking, MTProto testing, Xray/V2Ray config validation, public source scraping, and built-in update checking in one tool.

</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/0413df28-3e25-4d35-b03b-df09fbcede0c" alt="CT Banner" width="100%">
</p>

***

## Table of Contents

- [Overview](#overview)
- [Why CT](#why-ct)
- [What's New in 1.3.12](#whats-new-in-1312)
- [Features](#features)
- [Modules](#modules)
- [Interactive Mode](#interactive-mode)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
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

CT is built for users who need a single command-line tool to test network quality, validate proxy and Xray configs, manage scraping sources, and keep everything updated without leaving the terminal.

It is designed to be:
- fast for large lists,
- practical for daily use,
- easy to extend,
- and comfortable in both scripted and interactive workflows.

### Why CT

- **All-in-One** — DNS, proxy, MTProto, Xray, scraper, and update workflow in one binary.
- **Interactive** — A cleaner terminal UI with arrow-key navigation and number support.
- **Smart Defaults** — Prompts appear only when needed.
- **Cross-Platform** — Windows, Linux, and macOS support.
- **Concurrent** — Multi-threaded checks for speed.
- **System-Aware** — Can apply best DNS or proxy settings directly.
- **Source-Managed** — Scraper sources can be added, removed, reloaded, and displayed from within the app.

***

## What’s New in 1.3.12

This release focuses on usability, automation, and better source management.

### 1) Interactive UI improvements

The interactive menu is now more polished and easier to use. It supports:
- arrow-key navigation,
- highlighted selections,
- number-based selection,
- a branded startup banner,
- automatic cursor hide/show during menu use.

This makes the app feel much more responsive and pleasant in the terminal.

### 2) Smarter prompts

Several prompts are now conditional instead of always showing up. For example:
- DNS only asks for domains when HTTP testing is enabled.
- Proxy prompts can now stay out of the way unless they are actually needed.
- Xray-related prompts are more focused and reduce unnecessary input.

This keeps the flow cleaner and avoids repeated or irrelevant questions.

### 3) Scraper menu system

The scraper module now includes a built-in management menu for source handling:
- add a source,
- remove a source,
- reload configuration,
- show current configuration,
- run scraping directly.

This means source management is now available from inside the program instead of being limited to command-line flags.

### 4) Run scraper directly

`ct scrape run` now executes scraping immediately instead of opening the management menu first. This is useful when you just want the scraper to do its job without extra prompts.

### 5) Update checker

A new **Check Update** option was added to the main menu. It checks the version stored online and compares it with the local version.

If a newer version exists, CT tries the update in this order:
1. `go install github.com/batmanpriv/ct@vX.Y.Z`
2. GitHub release download on Windows
3. Clone repository and build from source

This gives users multiple ways to update depending on what tools are available on their system.

### 6) Better default handling

The program now behaves more consistently when users skip optional inputs:
- DNS defaults are applied automatically.
- Proxy and Xray optional fields only appear when needed.
- Empty values now fall back to safe defaults.

***

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
go install github.com/batmanpriv/ct@1.3.12
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

### Update

```bash
ct check-update
```

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

### Xray Config List

```txt
vless://...
vmess://...
trojan://...
ss://...
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

- DNS, proxy, MTProto, and Xray checks all use worker-based execution.
- Smart defaults reduce manual overhead.
- Cached and fallback-based flows reduce repeated work.
- Interactive prompts avoid asking for unnecessary values.
- Source operations are designed to be simple and responsive.

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
└── output/
```

## Changelog

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
