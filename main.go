package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/batmanpriv/ct/mtp"
	"github.com/batmanpriv/ct/pc"
	"github.com/batmanpriv/ct/scraper"
	"github.com/batmanpriv/ct/xp"
	"github.com/batmanpriv/ct/cf"

	"github.com/AlecAivazis/survey/v2"
	"github.com/miekg/dns"
)

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[37m"
	White   = "\033[97m"
	Bold    = "\033[1m"
)

const VERSION = "1.4.15"

type Module string

const (
	ModuleRoot     Module = "root"
	ModuleDNS      Module = "dns"
	ModuleProxy    Module = "proxy"
	ModuleXray     Module = "xray"
	ModuleMTProto  Module = "mtproto"
	ModuleScrape   Module = "scrape"
	ModuleInteract  Module = "interactive"
)

type DNSResult struct {
	DNS          string            `json:"dns"`
	Lookup       bool              `json:"lookup"`
	LookupMs     int64             `json:"lookup_ms"`
	UDP          bool              `json:"udp"`
	TCP          bool              `json:"tcp"`
	DNSSEC       bool              `json:"dnssec"`
	EDNS         bool              `json:"edns"`
	EDNSBuffer   int               `json:"edns_buffer"`
	IPv6         bool              `json:"ipv6"`
	HTTPS        bool              `json:"https"`
	HTTPSMs      int64             `json:"https_ms"`
	HTTPStatus   int               `json:"http_status"`
	HTTPBlocked  bool              `json:"http_blocked"`
	HTTPKind     string            `json:"http_kind"`
	HTTPError    string            `json:"http_error"`
	Redirects    int               `json:"redirects"`
	TLSVersion   string            `json:"tls_version"`
	CipherSuite  string            `json:"cipher_suite"`
	HTTP2        bool              `json:"http2"`
	DoT          bool              `json:"dot"`
	DoH          bool              `json:"doh"`
	DoTError     string            `json:"dot_error"`
	DoHError     string            `json:"doh_error"`
	Country      string            `json:"country"`
	ASN          string            `json:"asn"`
	Provider     string            `json:"provider"`
	Score        int               `json:"score"`
	Records      map[string]bool   `json:"records"`
	LookupError  string            `json:"lookup_error"`
	Extra        map[string]string `json:"extra"`
}

type Config struct {
	DNSFile      string
	Threads      int
	Domains      string
	Mode         int
	OutputJSON   bool
	Score        bool
	NoColor      bool
	SetDNS       string
	ApplyBest    bool
	Insecure     bool
	TestURL      string
	ProviderFile string
}

type ProviderEntry struct {
	Name string `json:"name"`
	DoH  string `json:"doh"`
	DoT  string `json:"dot"`
	SNI  string `json:"sni"`
	Host string `json:"host"`
}

type UIState struct {
	results    []DNSResult
	total      int
	completed  int32
	mu         sync.Mutex
	shouldQuit bool
}

type GeoInfo struct {
	Country  string
	Provider string
	ASN      string
}

type HTTPResult struct {
	Success     bool
	Status      int
	Kind        string
	Error       error
	TLSVersion  string
	CipherSuite string
	HTTP2       bool
	Blocked     bool
	DurationMs  int64
	Redirects   int
	FinalURL    string
}

var (
	cleanRegex      = regexp.MustCompile(`[^0-9a-zA-Z\.\:\-\[\]]`)
	uiState         = &UIState{}
	geoCache        sync.Map
	provCache       sync.Map
	mu              sync.Mutex
	httpClientCache sync.Map
	dohClientCache  sync.Map
)

func main() {
	app := &App{Args: os.Args[1:]}
	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

type App struct {
	Args []string
}

func (a *App) Run() error {
	ctx := &AppContext{
		RootDir: getExecutableDir(),
		Reader:  bufio.NewReader(os.Stdin),
	}

	if len(a.Args) == 0 {
		printRootHelp()
		return nil
	}

	switch strings.ToLower(a.Args[0]) {
	case "help", "-h", "--help":
		printRootHelp()
		return nil
	case string(ModuleInteract):
		return runInteractive(ctx)
	case string(ModuleDNS):
		return runDNSModule(ctx, a.Args[1:])
	case string(ModuleProxy):
		return runProxyModule(ctx, a.Args[1:])
	case string(ModuleXray):
		return runXrayModule(ctx, a.Args[1:])
	case string(ModuleMTProto):
		return runMTProtoModule(ctx, a.Args[1:])
	case string(ModuleScrape):
		return runScrapeModule(ctx, a.Args[1:])
	case "cf":
		return runCFModule(ctx, a.Args[1:])
	default:
		fmt.Println("Unknown command:", a.Args[0])
		printRootHelp()
		return nil
	}
}

type AppContext struct {
	RootDir string
	Reader  *bufio.Reader
}

func printRootHelp() {
	fmt.Println(`ct - modular CLI

Usage:
  ct <module> <command> [options]
  ct interactive

Modules:
  dns        DNS benchmark / test
  proxy      Proxy checker / downloader / scraper
  xray       Xray checker / downloader
  mtproto    MTProto checker / downloader
  scrape     Scraper utilities
  cf         Cloudflare IP scanner
  interactive Guided UI for normal users

Examples:
  ct dns help
  ct dns test dns.txt
  ct dns apply-best
  ct dns status
  ct dns set 1.1.1.1

  ct proxy check proxies.txt
  ct proxy download
  ct proxy scrape
  ct proxy apply-best

  ct xray download
  ct xray test config.txt

  ct mtproto check mtproto.txt
  ct mtproto download

  ct scrape run
  ct cf scan
  ct cf scan -workers 200 -ports 443,8443
  ct interactive`)
}

func runDNSModule(ctx *AppContext, args []string) error {
	if len(args) == 0 {
		printDNSHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "help", "-h", "--help":
		printDNSHelp()
		return nil

	case "test":
		return runDNSTest(ctx, args[1:])

	case "quick":
		return runDNSTestPreset(ctx, DNSModeQuick, args[1:])

	case "full":
		return runDNSTestPreset(ctx, DNSModeFull, args[1:])

	case "apply-best":
		return runDNSApplyBest(ctx, args[1:])

	case "status":
		checkDNSStatus()
		return nil

	case "set":
		if len(args) < 2 {
			return errors.New("missing DNS value")
		}
		setSystemDNS(args[1])
		return nil

	default:
		printDNSHelp()
		return nil
	}
}

func runProxyModule(ctx *AppContext, args []string) error {
	if len(args) == 0 {
		printProxyHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "help", "-h", "--help":
		printProxyHelp()
		return nil

	case "check":
		return runProxyCheck(ctx, args[1:])

	case "download":
		return runProxyDownload(ctx)

	case "scrape":
		return runProxyScrape(ctx)

	case "apply-best":
		return runProxyApplyBest(ctx)

	default:
		printProxyHelp()
		return nil
	}
}

func runXrayModule(ctx *AppContext, args []string) error {
	if len(args) == 0 {
		printXrayHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "help", "-h", "--help":
		printXrayHelp()
		return nil

	case "download":
		return runXrayDownload(ctx)

	case "test":
		return runXrayTest(ctx, args[1:])

	default:
		printXrayHelp()
		return nil
	}
}

func runMTProtoModule(ctx *AppContext, args []string) error {
	if len(args) == 0 {
		printMTProtoHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "help", "-h", "--help":
		printMTProtoHelp()
		return nil

	case "download":
		return runMTProtoDownload(ctx)

	case "check":
		return runMTProtoCheck(ctx, args[1:])

	default:
		printMTProtoHelp()
		return nil
	}
}

func runCFModule(ctx *AppContext, args []string) error {
	if len(args) == 0 {
		printCFHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "help", "-h", "--help":
		printCFHelp()
		return nil
	case "scan":
		return runCFScan(args[1:])
	default:
		printCFHelp()
		return nil
	}
}

func runScrapeModule(ctx *AppContext, args []string) error {
	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "run":
			return runScraperOnly("./output", 20, false)
		case "add-source":
			return scrapeAddSource(ctx)
		case "remove-source":
			return scrapeRemoveSource(ctx)
		case "reload":
			return scrapeReloadConfig(ctx)
		case "show-config":
			return scrapeShowConfig(ctx)
		case "help", "-h", "--help":
			printScrapeHelp()
			return nil
		}
	}

	for {
		choice, err := askChoiceDefault(ctx, "Scrape menu", []string{
			"Add source",
			"Remove source",
			"Reload config",
			"Show config",
			"Run scraper",
			"Back",
		}, 1)
		if err != nil {
			return err
		}

		switch choice {
		case 1:
			if err := scrapeAddSource(ctx); err != nil {
				fmt.Println(Red + "Error: " + err.Error() + Reset)
			}
		case 2:
			if err := scrapeRemoveSource(ctx); err != nil {
				fmt.Println(Red + "Error: " + err.Error() + Reset)
			}
		case 3:
			if err := scrapeReloadConfig(ctx); err != nil {
				fmt.Println(Red + "Error: " + err.Error() + Reset)
			}
		case 4:
			if err := scrapeShowConfig(ctx); err != nil {
				fmt.Println(Red + "Error: " + err.Error() + Reset)
			}
		case 5:
			if err := runScraperOnly("./output", 20, false); err != nil {
				fmt.Println(Red + "Error: " + err.Error() + Reset)
			}
		case 6:
			return nil
		}
	}
}

func scrapeAddSource(ctx *AppContext) error {
	url, err := askLine(ctx, "Source URL")
	if err != nil {
		return err
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return errors.New("empty source url")
	}

	sourceType, err := askYesNoDefault(ctx, "Do you know the source type?", false)
	if err != nil {
		return err
	}

	kind := ""
	if sourceType {
		kind, err = askLine(ctx, "Source type")
		if err != nil {
			return err
		}
		kind = strings.TrimSpace(kind)
	}

	s := scraper.NewScraper("./output", 20, false)
	if err := s.LoadConfig(); err != nil {
		return err
	}
	return s.AddSource(url, kind)
}

func scrapeRemoveSource(ctx *AppContext) error {
	url, err := askLine(ctx, "Source URL to remove")
	if err != nil {
		return err
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return errors.New("empty source url")
	}

	s := scraper.NewScraper("./output", 20, false)
	if err := s.LoadConfig(); err != nil {
		return err
	}
	return s.RemoveSource(url)
}

func scrapeReloadConfig(ctx *AppContext) error {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.LoadConfig(); err != nil {
		return err
	}
	return s.ReloadConfig()
}

func scrapeShowConfig(ctx *AppContext) error {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.LoadConfig(); err != nil {
		return err
	}
	return s.ShowConfig()
}

func runCFScan(args []string) error {
	config := &cf.ScanConfig{
		Sources:          []string{"cloudflare"},
		WorkerCount:      100,
		Ports:            []int{443, 80, 2053, 2083, 2087, 2096, 8443},
		EnableHTTP2:      true,
		EnableHTTP3:      true,
		EnableSpeedTest:  false,
		EnableGeoIP:      false,
		EnableReverseDNS: true,
		OutputFormat:     "json",
		OutputPath:       "results.json",
		TestDomain:       "www.cloudflare.com",
		RateLimit:        1000,
		RealTimePrint:    true,
		ShowProgress:     true,
		MaxResults:       20,
		Timeout:          5,
		PortScanTimeout:  2,
		SortBy:           "score",
		NoColor:          false,
		MaxIPsPerRange:   10000,
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-source":
			if i+1 < len(args) {
				config.Sources = strings.Split(args[i+1], ",")
				i++
			}
		case "-workers":
			if i+1 < len(args) {
				config.WorkerCount, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-ports":
			if i+1 < len(args) {
				portStrs := strings.Split(args[i+1], ",")
				var ports []int
				for _, p := range portStrs {
					if port, err := strconv.Atoi(p); err == nil {
						ports = append(ports, port)
					}
				}
				config.Ports = ports
				i++
			}
		case "-domain":
			if i+1 < len(args) {
				config.TestDomain = args[i+1]
				i++
			}
		case "-output":
			if i+1 < len(args) {
				config.OutputPath = args[i+1]
				i++
			}
		case "-format":
			if i+1 < len(args) {
				config.OutputFormat = args[i+1]
				i++
			}
		case "-geoip":
			if i+1 < len(args) {
				config.GeoIPDBPath = args[i+1]
				config.EnableGeoIP = true
				i++
			}
		case "-speed":
			config.EnableSpeedTest = true
		case "-timeout":
			if i+1 < len(args) {
				config.Timeout, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-port-timeout":
			if i+1 < len(args) {
				config.PortScanTimeout, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-max":
			if i+1 < len(args) {
				config.MaxResults, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-sort":
			if i+1 < len(args) {
				config.SortBy = args[i+1]
				i++
			}
		case "-quiet":
			config.RealTimePrint = false
		case "-noprogress":
			config.ShowProgress = false
		case "-nocolor":
			config.NoColor = true
		}
	}

	return cf.RunScanner(config)
}

func printCFHelp() {
	fmt.Println(`ct cf commands

Usage:
  ct cf scan [flags]

Flags:
  -source <source>         IP sources: cloudflare, bgp, asn13335, ipv6 or custom:file.txt
  -workers <num>           Number of workers (default: 100)
  -ports <ports>           Ports to scan (comma-separated)
  -domain <domain>         Test domain (default: www.cloudflare.com)
  -output <path>           Output file (default: results.json)
  -format <format>         Output format: json, csv, txt (default: json)
  -geoip <path>            GeoIP database path
  -speed                   Enable speed test
  -timeout <seconds>       HTTP/TLS timeout (default: 5)
  -port-timeout <seconds>  Port scan timeout (default: 2)
  -max <num>               Max results to show (default: 20)
  -sort <sort>             Sort by: score, latency (default: score)
  -quiet                   Disable real-time output
  -noprogress              Disable progress
  -nocolor                 Disable colors
  -help                    Show this help

Examples:
  ct cf scan
  ct cf scan -workers 200 -ports 443,8443
  ct cf scan -source custom:ips.txt -domain example.com -sort latency`)
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func hideCursor() {
	fmt.Print("\033[?25l")
}

func showCursor() {
	fmt.Print("\033[?25h")
}

func renderBanner() {
	clearScreen()
	fmt.Println(Bold + Magenta + "╔════════════════════════════════════╗" + Reset)
	fmt.Println(Bold + Magenta + "║            Check test | CT         ║" + Reset)
	fmt.Println(Bold + Magenta + "╚════════════════════════════════════╝" + Reset)
	fmt.Println()
	fmt.Println(Cyan + "GitHub   : https://github.com/batmanpriv" + Reset)
	fmt.Println(Green + "Telegram : https://t.me/BatmanPriv" + Reset)
	fmt.Println(Magenta + "VERSION : " + VERSION + Reset)
	fmt.Println(Yellow + "Use ↑ ↓ and Enter to navigate" + Reset)
	fmt.Println()
}

func runInteractive(ctx *AppContext) error {
	defer showCursor()
	hideCursor()
	renderBanner()

	choices := []string{
		"DNS Benchmark",
		"Proxy Checker",
		"MTProto Checker",
		"Xray Checker",
		"Scraper",
		"Cloudflare Scanner",
		"Check Update",
		"Exit",
	}

	for {
		var picked string
		err := survey.AskOne(&survey.Select{
			Message: "Choose module",
			Options: choices,
		}, &picked, survey.WithIcons(func(icons *survey.IconSet) {
			icons.Question.Text = Bold + Cyan + "❯" + Reset
			icons.SelectFocus.Text = Bold + Green + "➜" + Reset
			icons.MarkedOption.Text = Bold + Yellow + "●" + Reset
		}))
		if err != nil {
			return err
		}

		switch picked {
		case "DNS Benchmark":
			return interactiveDNS(ctx)
		case "Proxy Checker":
			return interactiveProxy(ctx)
		case "MTProto Checker":
			return interactiveMTProto(ctx)
		case "Xray Checker":
			return interactiveXray(ctx)
		case "Scraper":
			return interactiveScrape(ctx)
		case "Cloudflare Scanner":
			return interactiveCF(ctx)
		case "Check Update":
			if err := checkUpdate(); err != nil {
				fmt.Println(Red + "Error: " + err.Error() + Reset)
			}
		case "Exit":
			clearScreen()
			return nil
		}
	}
}

func checkUpdate() error {
	latest, err := fetchLatestVersion()
	if err != nil {
		return err
	}

	if normalizeVersion(latest) == normalizeVersion(VERSION) {
		fmt.Println(Green + "You are on the latest version: " + VERSION + Reset)
		return nil
	}

	fmt.Printf(Yellow+"New version found: %s -> %s\n"+Reset, VERSION, latest)
	return installUpdate(latest)
}

func interactiveCF(ctx *AppContext) error {
	fmt.Println("\n" + Cyan + "╔════════════════════════════════════════════╗" + Reset)
	fmt.Println(Cyan + "║        Cloudflare IP Scanner              ║" + Reset)
	fmt.Println(Cyan + "╚════════════════════════════════════════════╝" + Reset)
	fmt.Println()

	config := &cf.ScanConfig{
		Sources:          []string{"cloudflare"},
		WorkerCount:      100,
		Ports:            []int{443, 80, 2053, 2083, 2087, 2096, 8443},
		EnableHTTP2:      true,
		EnableHTTP3:      true,
		EnableSpeedTest:  false,
		EnableGeoIP:      false,
		EnableReverseDNS: true,
		OutputFormat:     "txt",
		OutputPath:       "valid_ips_" + time.Now().Format("20060102_150405") + ".txt",
		TestDomain:       "www.cloudflare.com",
		RateLimit:        1000,
		RealTimePrint:    true,
		ShowProgress:     true,
		MaxResults:       20,
		Timeout:          5,
		PortScanTimeout:  2,
		SortBy:           "score",
		NoColor:          false,
		MaxIPsPerRange:   10000,
	}

	defaultRanges := cf.GetCloudflareRanges()
	allRanges := cf.GetAllCloudflareRanges()
	
	fmt.Println(Green + "Default Cloudflare IP Ranges (fast scan):" + Reset)
	for _, r := range defaultRanges {
		fmt.Printf("  %s", r)
	}
	fmt.Println()
	
	timeStr, color := cf.EstimateScanTime(defaultRanges, config.WorkerCount, config.Ports, config.MaxIPsPerRange)
	fmt.Printf(color+"Estimated scan time with %d workers: %s\n"+Reset, config.WorkerCount, timeStr)

	fmt.Println("\n" + Yellow + "Additional ranges available (slower but more comprehensive):" + Reset)
	extraRanges := []string{}
	for _, r := range allRanges {
		isDefault := false
		for _, d := range defaultRanges {
			if r == d {
				isDefault = true
				break
			}
		}
		if !isDefault {
			extraRanges = append(extraRanges, r)
		}
	}
	
	for i, r := range extraRanges {
		if i%3 == 0 && i > 0 {
			fmt.Println()
		}
		fmt.Printf("  %s", r)
	}
	fmt.Println()
	
	allTimeStr, allColor := cf.EstimateScanTime(allRanges, config.WorkerCount, config.Ports, config.MaxIPsPerRange)
	fmt.Printf(allColor+"Full scan with all ranges would take: %s\n"+Reset, allTimeStr)
	
	fmt.Println("\n" + Cyan + "Select IP source type:" + Reset)
	fmt.Println("  1) Cloudflare default ranges (fast)")
	fmt.Println("  2) All Cloudflare ranges (comprehensive)")
	fmt.Println("  3) Custom CIDR range(s)")
	fmt.Println("  4) IP file (one IP per line)")
	
	sourceChoice, err := askIntDefault(ctx, "Choose", 1)
	if err != nil {
		return err
	}
	
	switch sourceChoice {
	case 1:
		config.Sources = []string{"cloudflare"}
	case 2:
		config.Sources = []string{"cloudflare_all"}
	case 3:
		customRange, err := askLine(ctx, "Enter CIDR range(s) (comma-separated, e.g., 104.16.0.0/13,172.64.0.0/13)")
		if err != nil {
			return err
		}
		if strings.TrimSpace(customRange) != "" {
			config.Sources = []string{"range:" + strings.TrimSpace(customRange)}
		}
	case 4:
		file, err := askLine(ctx, "IP file path (one IP per line or CIDR)")
		if err != nil {
			return err
		}
		if strings.TrimSpace(file) != "" {
			config.Sources = []string{"custom:" + strings.TrimSpace(file)}
		}
	}

	workers, err := askIntDefault(ctx, "Workers (default 100)", 100)
	if err != nil {
		return err
	}
	config.WorkerCount = workers

	portsInput, err := askLine(ctx, "Ports (comma-separated, default: 443,80,2053,2083,2087,2096,8443)")
	if err != nil {
		return err
	}
	if strings.TrimSpace(portsInput) != "" {
		var ports []int
		for _, p := range strings.Split(portsInput, ",") {
			if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ports = append(ports, port)
			}
		}
		if len(ports) > 0 {
			config.Ports = ports
		}
	}

	maxIPs, err := askIntDefault(ctx, "Max IPs per range (default 10000, 0 = unlimited)", 10000)
	if err != nil {
		return err
	}
	config.MaxIPsPerRange = maxIPs

	domain, err := askLine(ctx, "Test domain (default: www.cloudflare.com)")
	if err != nil {
		return err
	}
	if strings.TrimSpace(domain) != "" {
		config.TestDomain = domain
	}

	fmt.Println("\n" + Cyan + "╔════════════════════════════════════════════╗" + Reset)
	fmt.Println(Cyan + "║           Scan Configuration                ║" + Reset)
	fmt.Println(Cyan + "╚════════════════════════════════════════════╝" + Reset)
	fmt.Printf("%sSource:%s %v\n", Green, Reset, config.Sources)
	fmt.Printf("%sWorkers:%s %d\n", Green, Reset, config.WorkerCount)
	fmt.Printf("%sPorts:%s %v\n", Green, Reset, config.Ports)
	fmt.Printf("%sDomain:%s %s\n", Green, Reset, config.TestDomain)
	fmt.Printf("%sMax IPs per range:%s %d\n", Green, Reset, config.MaxIPsPerRange)
	
	var finalRanges []string
	if len(config.Sources) > 0 && strings.HasPrefix(config.Sources[0], "range:") {
		fmt.Printf("%sCustom ranges:%s %s\n", Yellow, Reset, strings.TrimPrefix(config.Sources[0], "range:"))
	} else if len(config.Sources) > 0 && strings.HasPrefix(config.Sources[0], "custom:") {
		fmt.Printf("%sIP file:%s %s\n", Yellow, Reset, strings.TrimPrefix(config.Sources[0], "custom:"))
	} else {
		if sourceChoice == 2 {
			finalRanges = allRanges
		} else {
			finalRanges = defaultRanges
		}
		finalTimeStr, finalColor := cf.EstimateScanTime(finalRanges, config.WorkerCount, config.Ports, config.MaxIPsPerRange)
		fmt.Printf("%sEstimated time:%s %s%s\n", Yellow, Reset, finalColor, finalTimeStr)
	}

	fmt.Println("\n" + Green + "Starting scan..." + Reset)

	if err := cf.RunScanner(config); err != nil {
		fmt.Println(Red + "Error: " + err.Error() + Reset)
		return err
	}

	fmt.Println("\n" + Yellow + "Press Enter to continue..." + Reset)
	ctx.Reader.ReadString('\n')

	return nil
}

func fetchLatestVersion() (string, error) {
	resp, err := http.Get("https://raw.githubusercontent.com/batmanpriv/ct/refs/heads/main/version.txt")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}

func installUpdate(ver string) error {
	ver = normalizeVersion(ver)

	if _, err := exec.LookPath("go"); err == nil {
		fmt.Println(Cyan + "Updating with go install..." + Reset)
		cmd := exec.Command("go", "install", "github.com/batmanpriv/ct@v"+ver)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	if runtime.GOOS == "windows" {
		fmt.Println(Cyan + "Downloading Windows release..." + Reset)
		return downloadWindowsRelease(ver)
	}

	if _, err := exec.LookPath("git"); err == nil {
		fmt.Println(Cyan + "Falling back to git clone + build..." + Reset)
		return cloneAndBuild(ver)
	}

	return errors.New("go, git, and release install all unavailable")
}

func downloadWindowsRelease(ver string) error {
	url := fmt.Sprintf("https://github.com/batmanpriv/ct/releases/download/%s/ct.exe", ver)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	out, err := os.Create("ct.exe")
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func cloneAndBuild(ver string) error {
	tmpDir := filepath.Join(os.TempDir(), "ct-updater")
	_ = os.RemoveAll(tmpDir)

	cmd := exec.Command("git", "clone", "https://github.com/batmanpriv/ct.git", tmpDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	if ver != "" {
		cmd = exec.Command("git", "-C", tmpDir, "checkout", "v"+ver)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}

	buildCmd := exec.Command("go", "build", "-o", "ct.exe", ".")
	buildCmd.Dir = tmpDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	return buildCmd.Run()
}

func askOptionalLine(ctx *AppContext, label string, def string) (string, error) {
	use, err := askYesNoDefault(ctx, "Set "+label+"?", false)
	if err != nil {
		return "", err
	}
	if !use {
		return def, nil
	}
	v, err := askLine(ctx, label)
	if err != nil {
		return "", err
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return def, nil
	}
	return v, nil
}

func printDNSHelp() {
	fmt.Println(`ct dns commands

Usage:
  ct dns test [file]
  ct dns quick [file]
  ct dns full [file]
  ct dns apply-best
  ct dns status
  ct dns set <ip>
  ct dns help

Examples:
  ct dns test dns.txt
  ct dns quick
  ct dns full
  ct dns apply-best
  ct dns status
  ct dns set 1.1.1.1

Smart defaults:
  dns.txt
  dns_servers.txt
  dns.csv
  input.txt

Wizard:
  ct interactive`)
}

func printProxyHelp() {
	fmt.Println(`ct proxy commands

Usage:
  ct proxy check [file]
  ct proxy download
  ct proxy scrape
  ct proxy apply-best

Examples:
  ct proxy check proxies.txt
  ct proxy download
  ct proxy scrape
  ct proxy apply-best`)
}

func printXrayHelp() {
	fmt.Println(`ct xray commands

Usage:
  ct xray download
  ct xray test [file]

Examples:
  ct xray download
  ct xray test config.txt`)
}

func printMTProtoHelp() {
	fmt.Println(`ct mtproto commands

Usage:
  ct mtproto download
  ct mtproto check [file]

Examples:
  ct mtproto download
  ct mtproto check mtproto.txt`)
}

func printScrapeHelp() {
	fmt.Println(`ct scrape commands

Usage:
  ct scrape run
  ct scrape add-source <url>
  ct scrape remove-source <url>
  ct scrape reload
  ct scrape show-config

Examples:
  ct scrape run
  ct scrape add-source https://example.com
  ct scrape show-config`)
}

func interactiveDNS(ctx *AppContext) error {
	dnsFile, err := resolveDNSFile(ctx, nil)
	if err != nil {
		return err
	}

	threads, err := askIntDefault(ctx, "Threads (default 10)", 10)
	if err != nil {
		return err
	}

	httpTest, err := askYesNoDefault(ctx, "Enable HTTP tests?", true)
	if err != nil {
		return err
	}

	domains := "cloudflare.com,google.com,github.com"
	if httpTest {
		domains, err = askLine(ctx, "Domains (comma separated)")
		if err != nil {
			return err
		}
		domains = strings.TrimSpace(domains)
		if domains == "" {
			domains = "cloudflare.com,google.com,github.com"
		}
	}

	sortChoice, err := askChoiceDefault(ctx, "Sort by", []string{"Speed", "Score"}, 1)
	if err != nil {
		return err
	}

	outputJSON, err := askYesNoDefault(ctx, "Output JSON?", false)
	if err != nil {
		return err
	}

	mode := 0
	if httpTest {
		mode = 1
	}

	cfg := Config{
		DNSFile:   dnsFile,
		Threads:   threads,
		Mode:      mode,
		OutputJSON: outputJSON,
		Score:     sortChoice == 2,
		Domains:   domains,
	}

	return runDNSBenchmark(ctx, cfg)
}

func interactiveProxy(ctx *AppContext) error {
	proxyFile, err := smartPickFile(ctx, []string{"proxies.txt", "proxy.txt", "input.txt"}, "Proxy file")
	if err != nil {
		return err
	}

	threads, err := askIntDefault(ctx, "Threads (default 50)", 50)
	if err != nil {
		return err
	}

	autoDetect, err := askYesNoDefault(ctx, "Auto detect proxy type?", true)
	if err != nil {
		return err
	}

	proxyTypes := ""
	if !autoDetect {
		proxyTypes, err = askLine(ctx, "Proxy types (example: http,socks5,ss,trojan)")
		if err != nil {
			return err
		}
		proxyTypes = strings.TrimSpace(proxyTypes)
	}

	testURL := ""
	if ask, err := askYesNoDefault(ctx, "Set proxy test URL?", false); err != nil {
		return err
	} else if ask {
		testURL, err = askLine(ctx, "Proxy test URL (default: http://httpbin.org/ip)")
		if err != nil {
			return err
		}
		testURL = strings.TrimSpace(testURL)
		if testURL == "" {
			testURL = "http://httpbin.org/ip"
		}
	}

	download, err := askYesNoDefault(ctx, "Download proxies first?", false)
	if err != nil {
		return err
	}

	scrape, err := askYesNoDefault(ctx, "Scrape proxies?", false)
	if err != nil {
		return err
	}

	applyBest, err := askYesNoDefault(ctx, "Apply best proxy?", false)
	if err != nil {
		return err
	}

	cfg := pc.Config{
		ProxyFile:  proxyFile,
		Threads:    threads,
		Types:      proxyTypes,
		AutoDetect: autoDetect,
		Download:   download,
		Scrape:     scrape,
		ApplyBest:  applyBest,
		Timeout:    3,
		TestURL:    testURL,
	}

	pc.RunProxyChecker(cfg)
	return nil
}

func interactiveXray(ctx *AppContext) error {
	xrayFile, err := smartPickFile(ctx, []string{"config.txt", "xray.txt", "input.txt"}, "Xray config file")
	if err != nil {
		return err
	}

	download, err := askYesNoDefault(ctx, "Download configs?", false)
	if err != nil {
		return err
	}

	limit, err := askIntDefault(ctx, "Limit configs (0 = no limit)", 0)
	if err != nil {
		return err
	}

	threads, err := askIntDefault(ctx, "Threads (default 30)", 30)
	if err != nil {
		return err
	}

	testURL := ""
	if ask, err := askYesNoDefault(ctx, "Set xray test URL?", false); err != nil {
		return err
	} else if ask {
		testURL, err = askLine(ctx, "xray test URL (default: http://httpbin.org/ip)")
		if err != nil {
			return err
		}
		testURL = strings.TrimSpace(testURL)
		if testURL == "" {
			testURL = "http://httpbin.org/ip"
		}
	}

	timeout, err := askIntDefault(ctx, "Timeout seconds (default 2)", 2)
	if err != nil {
		return err
	}

	outputFile, err := askLine(ctx, "Output file (default alive_configs.txt)")
	if err != nil {
		return err
	}
	if strings.TrimSpace(outputFile) == "" {
		outputFile = "alive_configs.txt"
	}

	cfg := xp.CheckerConfig{
		ConfigFile: xrayFile,
		Download:   download,
		Limit:      limit,
		Threads:    threads,
		Timeout:    float64(timeout),
		OutputFile: outputFile,
		TestURL:    testURL,
	}

	xp.RunChecker(cfg)
	return nil
}

func interactiveMTProto(ctx *AppContext) error {
	mtprotoFile, err := smartPickFile(ctx, []string{"mtproto.txt", "mtproto_proxies.txt", "input.txt"}, "MTProto file")
	if err != nil {
		return err
	}

	threads, err := askIntDefault(ctx, "Threads (default 20)", 20)
	if err != nil {
		return err
	}

	timeout, err := askIntDefault(ctx, "Timeout seconds (default 2)", 2)
	if err != nil {
		return err
	}

	download, err := askYesNoDefault(ctx, "Download MTProto proxies?", false)
	if err != nil {
		return err
	}

	outputFile, err := askLine(ctx, "Output file (default valid_mtproto.txt)")
	if err != nil {
		return err
	}
	if strings.TrimSpace(outputFile) == "" {
		outputFile = "valid_mtproto.txt"
	}

	cfg := mtp.CheckerConfig{
		File:       mtprotoFile,
		Threads:    threads,
		Timeout:    time.Duration(timeout) * time.Second,
		Download:   download,
		OutputFile: outputFile,
		NoColor:    false,
	}

	checker := mtp.NewChecker(cfg)
	return checker.Run()
}

func interactiveScrape(ctx *AppContext) error {
	outputDir, err := askLine(ctx, "Output directory (default ./output)")
	if err != nil {
		return err
	}
	if strings.TrimSpace(outputDir) == "" {
		outputDir = "./output"
	}

	workers, err := askIntDefault(ctx, "Workers (default 20)", 20)
	if err != nil {
		return err
	}

	skipTelegram, err := askYesNoDefault(ctx, "Skip Telegram scraping?", false)
	if err != nil {
		return err
	}

	s := scraper.NewScraper(outputDir, workers, skipTelegram)
	if err := s.LoadConfig(); err != nil {
		return err
	}
	return s.Run()
}

func askLine(ctx *AppContext, prompt string) (string, error) {
	fmt.Printf("%s: ", prompt)
	line, err := ctx.Reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func askYesNoDefault(ctx *AppContext, prompt string, def bool) (bool, error) {
	tag := "[Y/n]"
	if !def {
		tag = "[y/N]"
	}

	for {
		v, err := askLine(ctx, prompt+" "+tag)
		if err != nil {
			return false, err
		}
		if v == "" {
			return def, nil
		}
		switch strings.ToLower(v) {
		case "y", "yes", "true", "1":
			return true, nil
		case "n", "no", "false", "0":
			return false, nil
		default:
			fmt.Println("Please answer y or n")
		}
	}
}

func askIntDefault(ctx *AppContext, prompt string, def int) (int, error) {
	for {
		v, err := askLine(ctx, fmt.Sprintf("%s [%d]", prompt, def))
		if err != nil {
			return 0, err
		}
		if v == "" {
			return def, nil
		}
		n, err := strconv.Atoi(v)
		if err == nil {
			return n, nil
		}
		fmt.Println("Invalid number")
	}
}

func askChoiceDefault(ctx *AppContext, prompt string, choices []string, def int) (int, error) {
	fmt.Println(prompt)
	for i, c := range choices {
		fmt.Printf("  %d) %s\n", i+1, c)
	}
	for {
		v, err := askLine(ctx, fmt.Sprintf("Choose [%d]", def))
		if err != nil {
			return 0, err
		}
		if v == "" {
			return def, nil
		}
		n, err := strconv.Atoi(v)
		if err == nil && n >= 1 && n <= len(choices) {
			return n, nil
		}
		fmt.Println("Invalid choice")
	}
}

func smartPickFile(ctx *AppContext, candidates []string, label string) (string, error) {
	for _, name := range candidates {
		if path := findFile(ctx.RootDir, name); path != "" {
			fmt.Printf("Found %s\n", filepath.Base(path))
			use, err := askYesNoDefault(ctx, "Use it?", true)
			if err != nil {
				return "", err
			}
			if use {
				return path, nil
			}
		}
	}

	v, err := askLine(ctx, label)
	if err != nil {
		return "", err
	}
	return v, nil
}

func findFile(root, name string) string {
	candidates := []string{
		filepath.Join(root, name),
		filepath.Join(root, "assets", name),
		filepath.Join(root, "data", name),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func getExecutableDir() string {
	exe, err := os.Executable()
	if err != nil {
		cwd, _ := os.Getwd()
		return cwd
	}
	return filepath.Dir(exe)
}

func runDNSBenchmark(ctx *AppContext, config Config) error {
	if config.DNSFile == "" {
		return errors.New("missing dns file")
	}

	if config.Threads < 2 {
		config.Threads = 2
	}
	if config.Domains == "" {
		config.Domains = "cloudflare.com,google.com,github.com"
	}

	if config.SetDNS != "" {
		if config.SetDNS == "status" {
			checkDNSStatus()
			return nil
		}
		setSystemDNS(config.SetDNS)
		return nil
	}

	if config.ApplyBest {
		registry := loadProviderRegistry(config.ProviderFile)
		best := findAndApplyBestDNS(config, registry)
		if best != "" {
			fmt.Printf("\n%s✓ Best DNS (%s) applied to system%s\n", Green, best, Reset)
		}
		return nil
	}

	domains := parseDomains(config.Domains, config.TestURL)

	dnsList, err := loadDNSList(config.DNSFile)
	if err != nil {
		return err
	}
	if len(dnsList) == 0 {
		return errors.New("no valid dns servers found")
	}

	registry := loadProviderRegistry(config.ProviderFile)

	uiState = &UIState{total: len(dnsList)}
	go uiLoop(config)

	jobs := make(chan string, len(dnsList))
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dnsServer := range jobs {
				result := testDNS(dnsServer, domains, config, registry)
				if result.Lookup {
					uiState.mu.Lock()
					uiState.results = append(uiState.results, result)
					uiState.mu.Unlock()
					saveValidDNS(dnsServer)
				}
				atomic.AddInt32(&uiState.completed, 1)
			}
		}()
	}

	for _, dnsServer := range dnsList {
		jobs <- dnsServer
	}
	close(jobs)
	wg.Wait()

	uiState.mu.Lock()
	uiState.shouldQuit = true
	uiState.mu.Unlock()

	time.Sleep(300 * time.Millisecond)

	if config.OutputJSON {
		saveJSON(uiState.results)
	}

	printSummary(uiState.results, config)
	printRecommendation(uiState.results, config)
	return nil
}

func runDNSTest(ctx *AppContext, args []string) error {
	file, err := resolveDNSFile(ctx, args)
	if err != nil {
		return err
	}

	cfg := Config{
		DNSFile: file,
		Threads: 10,
		Mode:    0,
		Domains: "cloudflare.com,google.com,github.com",
	}
	return runDNSBenchmark(ctx, cfg)
}

func runDNSTestPreset(ctx *AppContext, mode DNSMode, args []string) error {
	file, err := resolveDNSFile(ctx, args)
	if err != nil {
		return err
	}

	cfg := Config{
		DNSFile: file,
		Threads: 10,
		Mode:    0,
		Domains: "google.com",
	}

	if mode == DNSModeFull {
		cfg.Mode = 1
		cfg.Score = true
		cfg.Domains = "github.com,cloudflare.com"
	}

	return runDNSBenchmark(ctx, cfg)
}

func resolveDNSFile(ctx *AppContext, args []string) (string, error) {
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		return strings.TrimSpace(args[0]), nil
	}

	if path := findFile(ctx.RootDir, "dns.txt"); path != "" {
		fmt.Printf("Found %s\n", filepath.Base(path))
		use, err := askYesNoDefault(ctx, "Use it?", true)
		if err != nil {
			return "", err
		}
		if use {
			return path, nil
		}
	}

	for _, name := range []string{"dns_servers.txt", "dns.csv", "input.txt"} {
		if path := findFile(ctx.RootDir, name); path != "" {
			fmt.Printf("Found %s\n", filepath.Base(path))
			use, err := askYesNoDefault(ctx, "Use it?", true)
			if err != nil {
				return "", err
			}
			if use {
				return path, nil
			}
		}
	}

	if p := getDefaultResolversPath(ctx.RootDir); p != "" {
		fmt.Printf("Found %s\n", filepath.Base(p))
		use, err := askYesNoDefault(ctx, "Use it?", true)
		if err != nil {
			return "", err
		}
		if use {
			return p, nil
		}
	}

	return askLine(ctx, "DNS file")
}

func getDefaultResolversPath(root string) string {
	for _, p := range []string{
		filepath.Join(root, "resolvers.txt"),
		filepath.Join(root, "assets", "resolvers.txt"),
		filepath.Join(root, "data", "resolvers.txt"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func loadDNSList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.Trim(line, "\uFEFF")
		if line == "" {
			continue
		}
		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)
		line = strings.TrimSpace(cleanRegex.ReplaceAllString(line, ""))
		if line != "" {
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}

func loadProviderRegistry(path string) map[string]ProviderEntry {
	defaults := map[string]ProviderEntry{
		"1.1.1.1":         {Name: "Cloudflare", DoH: "https://cloudflare-dns.com/dns-query", DoT: "1.1.1.1:853", SNI: "cloudflare-dns.com", Host: "cloudflare-dns.com"},
		"1.0.0.1":         {Name: "Cloudflare", DoH: "https://cloudflare-dns.com/dns-query", DoT: "1.0.0.1:853", SNI: "cloudflare-dns.com", Host: "cloudflare-dns.com"},
		"8.8.8.8":         {Name: "Google", DoH: "https://dns.google/dns-query", DoT: "8.8.8.8:853", SNI: "dns.google", Host: "dns.google"},
		"8.8.4.4":         {Name: "Google", DoH: "https://dns.google/dns-query", DoT: "8.8.4.4:853", SNI: "dns.google", Host: "dns.google"},
		"9.9.9.9":         {Name: "Quad9", DoH: "https://dns.quad9.net/dns-query", DoT: "9.9.9.9:853", SNI: "dns.quad9.net", Host: "dns.quad9.net"},
		"149.112.112.112": {Name: "Quad9", DoH: "https://dns.quad9.net/dns-query", DoT: "149.112.112.112:853", SNI: "dns.quad9.net", Host: "dns.quad9.net"},
		"94.140.14.14":    {Name: "AdGuard", DoH: "https://dns.adguard-dns.com/dns-query", DoT: "94.140.14.14:853", SNI: "dns.adguard-dns.com", Host: "dns.adguard-dns.com"},
		"94.140.15.15":    {Name: "AdGuard", DoH: "https://dns.adguard-dns.com/dns-query", DoT: "94.140.15.15:853", SNI: "dns.adguard-dns.com", Host: "dns.adguard-dns.com"},
		"76.76.19.19":     {Name: "ControlD", DoH: "https://freedns.controld.com/dns-query", DoT: "76.76.19.19:853", SNI: "freedns.controld.com", Host: "freedns.controld.com"},
		"76.223.122.150":  {Name: "ControlD", DoH: "https://freedns.controld.com/dns-query", DoT: "76.223.122.150:853", SNI: "freedns.controld.com", Host: "freedns.controld.com"},
		"45.90.28.0":      {Name: "NextDNS", DoH: "https://dns.nextdns.io/dns-query", DoT: "45.90.28.0:853", SNI: "dns.nextdns.io", Host: "dns.nextdns.io"},
		"45.90.30.0":      {Name: "NextDNS", DoH: "https://dns.nextdns.io/dns-query", DoT: "45.90.30.0:853", SNI: "dns.nextdns.io", Host: "dns.nextdns.io"},
	}

	if path == "" {
		return defaults
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return defaults
	}

	var raw map[string]ProviderEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return defaults
	}

	for k, v := range raw {
		if v.Host == "" {
			v.Host = hostFromURL(v.DoH)
		}
		if v.SNI == "" {
			v.SNI = v.Host
		}
		if v.DoT == "" && k != "" {
			v.DoT = net.JoinHostPort(k, "853")
		}
		if v.DoH == "" && v.Host != "" {
			v.DoH = "https://" + v.Host + "/dns-query"
		}
		raw[k] = v
	}
	for k, v := range raw {
		defaults[k] = v
	}
	return defaults
}

func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u := strings.TrimSpace(raw)
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

func getProvider(server string, registry map[string]ProviderEntry) ProviderEntry {
	if v, ok := provCache.Load(server); ok {
		if p, ok := v.(ProviderEntry); ok {
			return p
		}
	}
	if p, ok := registry[server]; ok {
		provCache.Store(server, p)
		return p
	}
	p := ProviderEntry{
		Name: "Unknown",
		DoT:  net.JoinHostPort(server, "853"),
		SNI:  server,
		Host: server,
	}
	provCache.Store(server, p)
	return p
}

func randomCacheBusterDomain(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return "google.com"
	}
	if strings.HasPrefix(base, "http://") || strings.HasPrefix(base, "https://") {
		return base
	}
	prefix := fmt.Sprintf("ct-%d-%d", time.Now().UnixNano(), os.Getpid())
	return prefix + "." + base
}

func tlsCipherSuiteString(cipher uint16) string {
	if name := tls.CipherSuiteName(cipher); name != "" {
		return name
	}
	return fmt.Sprintf("0x%x", cipher)
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func checkDNSStatus() {
	fmt.Printf("\n%sCurrent DNS Settings:%s\n", Cyan, Reset)
	fmt.Println(strings.Repeat("-", 40))

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("netsh", "interface", "ipv4", "show", "dns")
		output, _ := cmd.Output()
		fmt.Println(string(output))

	case "linux":
		cmd := exec.Command("systemd-resolve", "--status")
		if output, err := cmd.Output(); err == nil {
			fmt.Println(string(output))
			return
		}
		cmd = exec.Command("cat", "/etc/resolv.conf")
		output, _ := cmd.Output()
		fmt.Println(string(output))

	case "darwin":
		for _, svc := range []string{"Wi-Fi", "Ethernet"} {
			cmd := exec.Command("networksetup", "-getdnsservers", svc)
			output, _ := cmd.Output()
			fmt.Printf("%s DNS:\n%s\n", svc, string(output))
		}

	default:
		fmt.Printf("Unsupported OS: %s\n", runtime.GOOS)
	}
}

func setSystemDNS(dnsServer string) {
	fmt.Printf("\n%sSetting system DNS to: %s%s\n", Cyan, dnsServer, Reset)
	fmt.Println(strings.Repeat("-", 40))

	if runtime.GOOS == "windows" {
		if err := exec.Command("net", "session").Run(); err != nil {
			fmt.Printf("%s⚠️ You need to run as Administrator!%s\n", Yellow, Reset)
			return
		}
	}

	switch runtime.GOOS {
	case "windows":
		setWindowsDNS(dnsServer)
	case "linux":
		setLinuxDNS(dnsServer)
	case "darwin":
		setMacDNS(dnsServer)
	default:
		fmt.Printf("Unsupported OS: %s\n", runtime.GOOS)
	}
}

func setWindowsDNS(dnsServer string) {
	interfaces := []string{"Wi-Fi", "Ethernet", "Ethernet 2"}
	var ifaceName string

	for _, name := range interfaces {
		cmd := exec.Command("powershell", "-Command",
			fmt.Sprintf(`Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Name -eq "%s"} | Select-Object -First 1 | ForEach-Object { $_.Name }`, name))
		output, err := cmd.Output()
		if err == nil {
			ifaceName = strings.TrimSpace(string(output))
			if ifaceName != "" {
				break
			}
		}
	}

	if ifaceName == "" {
		cmd := exec.Command("powershell", "-Command",
			`Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1 | ForEach-Object { $_.Name }`)
		output, err := cmd.Output()
		if err != nil {
			fmt.Println("Error finding network interface:", err)
			return
		}
		ifaceName = strings.TrimSpace(string(output))
	}

	if ifaceName == "" {
		fmt.Println("No active network interface found")
		return
	}

	_ = exec.Command("netsh", "interface", "ipv4", "set", "dns", fmt.Sprintf(`name="%s"`, ifaceName), "static", dnsServer, "primary").Run()
	fmt.Printf("%s✓ DNS set to %s (Interface: %s)%s\n", Green, dnsServer, ifaceName, Reset)
	_ = exec.Command("ipconfig", "/flushdns").Run()
}

func setLinuxDNS(dnsServer string) {
	if err := exec.Command("resolvectl", "dns", "eth0", dnsServer).Run(); err == nil {
		fmt.Printf("%s✓ DNS set to %s using resolvectl%s\n", Green, dnsServer, Reset)
		return
	}
	if err := exec.Command("systemd-resolve", "--set-dns="+dnsServer, "--interface=eth0").Run(); err == nil {
		fmt.Printf("%s✓ DNS set to %s using systemd-resolved%s\n", Green, dnsServer, Reset)
		return
	}

	resolvConf := fmt.Sprintf("nameserver %s\n", dnsServer)
	cmd := exec.Command("sh", "-c", "printf '%s' \""+strings.ReplaceAll(resolvConf, `"`, `\"`)+"\" | sudo tee /etc/resolv.conf > /dev/null")
	if err := cmd.Run(); err != nil {
		fmt.Println("Error setting DNS. Try running with sudo:", err)
		return
	}
	fmt.Printf("%s✓ DNS set to %s in /etc/resolv.conf%s\n", Green, dnsServer, Reset)
}

func setMacDNS(dnsServer string) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error finding network service:", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	var service string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "*") && !strings.Contains(line, "Bluetooth") {
			service = line
			break
		}
	}

	if service == "" {
		fmt.Println("No active network service found")
		return
	}

	cmd = exec.Command("networksetup", "-setdnsservers", service, dnsServer)
	if err := cmd.Run(); err != nil {
		fmt.Println("Error setting DNS:", err)
		return
	}
	fmt.Printf("%s✓ DNS set to %s (Service: %s)%s\n", Green, dnsServer, service, Reset)
}

func saveValidDNS(dnsServer string) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile("valid_dns_"+time.Now().Format("20060102")+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(dnsServer + "\n")
}

func saveJSON(results []DNSResult) {
	file, err := os.Create("results.json")
	if err != nil {
		fmt.Println("Error creating JSON:", err)
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
	fmt.Println("\nResults saved to results.json")
}

func testDNS(server string, domains []string, config Config, registry map[string]ProviderEntry) DNSResult {
	result := DNSResult{
		DNS:     server,
		Records: map[string]bool{},
		Extra:   map[string]string{},
	}

	host, port := parseDNSAddress(server)
	if host == "" {
		result.LookupError = "empty dns server"
		result.Score = calculateScore(result)
		return result
	}

	provider := getProvider(server, registry)
	result.Provider = provider.Name

	lookupDomain := domains[0]
	timeout := 4 * time.Second

	start := time.Now()
	ips, resp, err := dnsLookup(host, port, lookupDomain, dns.TypeA, timeout)
	if err != nil || len(ips) == 0 {
		ips, resp, err = dnsLookup(host, port, lookupDomain, dns.TypeAAAA, timeout)
	}
	result.LookupMs = time.Since(start).Milliseconds()

	if err != nil {
		result.LookupError = err.Error()
		result.Score = calculateScore(result)
		return result
	}
	if len(ips) == 0 {
		result.LookupError = "no ip returned"
		result.Score = calculateScore(result)
		return result
	}

	result.Lookup = true
	ip := ips[0]

	result.UDP, _ = testUDP(host, port, timeout)
	result.TCP, _ = testTCP(host, port, lookupDomain, timeout)

	if ad, err := testDNSSEC(host, port, lookupDomain, timeout); err == nil {
		result.DNSSEC = ad
	}

	if edns, buf, err := testEDNS(host, port, lookupDomain, timeout); err == nil {
		result.EDNS = edns
		result.EDNSBuffer = buf
	}

	if _, _, err := dnsLookup(host, port, lookupDomain, dns.TypeAAAA, timeout); err == nil {
		result.IPv6 = true
	}

	for _, d := range domains {
		for _, rt := range []struct {
			name  string
			qtype uint16
		}{
			{"A", dns.TypeA},
			{"AAAA", dns.TypeAAAA},
			{"MX", dns.TypeMX},
			{"TXT", dns.TypeTXT},
			{"CNAME", dns.TypeCNAME},
			{"NS", dns.TypeNS},
			{"SOA", dns.TypeSOA},
		} {
			if _, _, err := dnsLookup(host, port, d, rt.qtype, timeout); err == nil {
				result.Records[rt.name] = true
			}
		}
		break
	}

	country, isp, asn := getGeoIP(ip)
	result.Country = country
	result.ASN = asn
	result.Extra["isp"] = isp

	if config.Mode >= 1 {
		redirects := 0
		httpStart := time.Now()
		httpResult := testHTTP(lookupDomain, provider, 5*time.Second, config.Insecure, host, &redirects)
		result.HTTPSMs = time.Since(httpStart).Milliseconds()
		result.Redirects = redirects

		if httpResult.Error == nil && httpResult.Success {
			result.HTTPS = true
			result.HTTPStatus = httpResult.Status
			result.HTTPBlocked = httpResult.Blocked
			result.HTTPKind = httpResult.Kind
			result.TLSVersion = httpResult.TLSVersion
			result.CipherSuite = httpResult.CipherSuite
			result.HTTP2 = httpResult.HTTP2
		} else if httpResult.Error != nil {
			result.HTTPError = httpResult.Error.Error()
		}

		if ok, err := testDoT(host, provider, lookupDomain, config.Insecure, 5*time.Second); err == nil {
			result.DoT = ok
		} else {
			result.DoTError = err.Error()
		}

		if ok, err := testDoH(host, provider, lookupDomain, 5*time.Second, config.Insecure); err == nil {
			result.DoH = ok
		} else {
			result.DoHError = err.Error()
		}
	}

	result.Score = calculateScore(result)
	_ = resp
	return result
}

func dnsLookup(server string, port int, domain string, qtype uint16, timeout time.Duration) ([]string, *dns.Msg, error) {
	c := &dns.Client{Timeout: timeout, Net: "udp"}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		m.SetEdns0(4096, true)
	}

	addr := net.JoinHostPort(server, strconv.Itoa(port))
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		c.Net = "tcp"
		resp, _, err = c.Exchange(m, addr)
		if err != nil {
			return nil, nil, err
		}
	}

	if resp == nil {
		return nil, nil, errors.New("nil dns response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, resp, fmt.Errorf("dns rcode %s", dns.RcodeToString[resp.Rcode])
	}

	var out []string
	for _, ans := range resp.Answer {
		switch a := ans.(type) {
		case *dns.A:
			out = append(out, a.A.String())
		case *dns.AAAA:
			out = append(out, a.AAAA.String())
		case *dns.CNAME:
			out = append(out, a.Target)
		case *dns.NS:
			out = append(out, a.Ns)
		case *dns.MX:
			out = append(out, a.Mx)
		case *dns.TXT:
			out = append(out, strings.Join(a.Txt, " "))
		case *dns.SOA:
			out = append(out, a.Ns)
		}
	}

	if len(out) == 0 {
		return nil, resp, errors.New("no answer records")
	}

	return out, resp, nil
}

func testDNSSEC(server string, port int, domain string, timeout time.Duration) (bool, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetDo()
	opt.SetUDPSize(4096)
	m.Extra = append(m.Extra, opt)

	c := &dns.Client{Timeout: timeout}
	resp, _, err := c.Exchange(m, net.JoinHostPort(server, strconv.Itoa(port)))
	if err != nil {
		return false, err
	}
	if resp == nil {
		return false, errors.New("nil dns response")
	}
	if resp.AuthenticatedData {
		return true, nil
	}
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true, nil
		}
	}
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true, nil
		}
	}
	return false, nil
}

func testEDNS(server string, port int, domain string, timeout time.Duration) (bool, int, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	c := &dns.Client{Timeout: timeout}
	resp, _, err := c.Exchange(m, net.JoinHostPort(server, strconv.Itoa(port)))
	if err != nil {
		return false, 0, err
	}
	if resp == nil {
		return false, 0, errors.New("nil dns response")
	}

	for _, extra := range resp.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			if opt, ok := extra.(*dns.OPT); ok {
				return true, int(opt.Hdr.Class), nil
			}
		}
	}
	return false, 0, nil
}

func newReusableHTTPClient(server string, provider ProviderEntry, timeout time.Duration, insecure bool, customDNS bool, redirects *int) *http.Client {
	cacheKey := fmt.Sprintf("http|%s|%s|%t|%t", server, provider.Host, insecure, customDNS)
	if v, ok := httpClientCache.Load(cacheKey); ok {
		if c, ok := v.(*http.Client); ok {
			return c
		}
	}

	resolver := &net.Resolver{PreferGo: true}
	if customDNS {
		resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		}
	}

	dialer := &net.Dialer{Timeout: timeout}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if !customDNS {
				return dialer.DialContext(ctx, network, address)
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, errors.New("no ip resolved")
			}
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, errors.New("all dial attempts failed")
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
			ServerName:         provider.SNI,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2:    true,
		MaxIdleConns:         50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:      60 * time.Second,
		TLSHandshakeTimeout:  timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if redirects != nil {
			*redirects = len(via)
		}
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	httpClientCache.Store(cacheKey, client)
	return client
}

func newReusableDoHClient(server string, provider ProviderEntry, timeout time.Duration, insecure bool) *http.Client {
	cacheKey := fmt.Sprintf("doh|%s|%s|%t", server, provider.Host, insecure)
	if v, ok := dohClientCache.Load(cacheKey); ok {
		if c, ok := v.(*http.Client); ok {
			return c
		}
	}
	client := newReusableHTTPClient(server, provider, timeout, insecure, true, nil)
	dohClientCache.Store(cacheKey, client)
	return client
}

func classifyHTTPStatus(status int) (bool, string) {
	switch status {
	case 200, 201, 204:
		return false, "ok"
	case 301, 302, 303, 307, 308:
		return false, "redirect"
	case 403:
		return true, "forbidden"
	case 404:
		return true, "not_found_or_blocked"
	case 429:
		return true, "rate_limited"
	case 451:
		return true, "legal_block"
	case 500, 502, 503, 504:
		return true, "server_error"
	default:
		if status >= 400 {
			return true, "http_error"
		}
		return false, "other"
	}
}

func readBodySnippet(r io.Reader, limit int) string {
	if limit <= 0 {
		limit = 256
	}
	b, _ := io.ReadAll(io.LimitReader(r, int64(limit)))
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func testUDP(server string, port int, timeout time.Duration) (bool, error) {
	_, _, err := dnsLookup(server, port, "google.com", dns.TypeA, timeout)
	return err == nil, err
}

func testTCP(server string, port int, domain string, timeout time.Duration) (bool, error) {
	c := &dns.Client{Timeout: timeout, Net: "tcp"}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	resp, _, err := c.Exchange(m, net.JoinHostPort(server, strconv.Itoa(port)))
	if err != nil {
		return false, err
	}
	if resp == nil {
		return false, errors.New("nil dns response")
	}
	return resp.Rcode == dns.RcodeSuccess, nil
}

func testDoT(server string, provider ProviderEntry, domain string, insecure bool, timeout time.Duration) (bool, error) {
	host := provider.SNI
	if host == "" {
		host = provider.Host
	}
	if host == "" {
		host = server
	}

	target := provider.DoT
	if target == "" {
		target = net.JoinHostPort(server, "853")
	}

	c := &dns.Client{
		Timeout: timeout,
		Net:     "tcp-tls",
		TLSConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		},
	}

	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := c.Exchange(m, target)
	if err != nil {
		return false, err
	}
	if resp == nil {
		return false, errors.New("nil dns response")
	}
	return resp.Rcode == dns.RcodeSuccess, nil
}

func testDoH(server string, provider ProviderEntry, domain string, timeout time.Duration, insecure bool) (bool, error) {
	endpoint := provider.DoH
	if endpoint == "" {
		return false, errors.New("doh endpoint not configured")
	}

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	wire, err := msg.Pack()
	if err != nil {
		return false, err
	}

	client := newReusableDoHClient(server, provider, timeout, insecure)

	try := func(method string) (bool, error) {
		var req *http.Request

		if method == http.MethodGet {
			q := base64.RawURLEncoding.EncodeToString(wire)
			url := endpoint
			if strings.Contains(url, "?") {
				url += "&dns=" + q
			} else {
				url += "?dns=" + q
			}
			req, err = http.NewRequest(http.MethodGet, url, nil)
		} else {
			req, err = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(wire))
			if err == nil {
				req.Header.Set("Content-Type", "application/dns-message")
			}
		}
		if err != nil {
			return false, err
		}
		req.Header.Set("Accept", "application/dns-message")

		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("doh http status %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		dnsResp := &dns.Msg{}
		if err := dnsResp.Unpack(body); err != nil {
			return false, err
		}
		if dnsResp.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("doh rcode %s", dns.RcodeToString[dnsResp.Rcode])
		}
		return len(dnsResp.Answer) > 0, nil
	}

	if ok, err := try(http.MethodGet); err == nil && ok {
		return true, nil
	}
	return try(http.MethodPost)
}

func getGeoIP(ip string) (string, string, string) {
	if v, ok := geoCache.Load(ip); ok {
		if g, ok := v.(GeoInfo); ok {
			return g.Country, g.Provider, g.ASN
		}
	}

	var country, provider, asn string
	apis := []string{
		fmt.Sprintf("https://ipinfo.io/%s/json", ip),
		fmt.Sprintf("https://ipwhois.app/json/%s", ip),
		fmt.Sprintf("https://ip-api.com/json/%s?fields=countryCode,isp,as", ip),
	}

	for _, u := range apis {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		func() {
			defer resp.Body.Close()
			var m map[string]any
			if json.NewDecoder(resp.Body).Decode(&m) != nil {
				return
			}
			switch {
			case strings.Contains(u, "ipinfo.io"):
				if v, _ := m["country"].(string); v != "" {
					country = v
				}
				if v, _ := m["org"].(string); v != "" {
					provider = v
				}
			case strings.Contains(u, "ipwhois.app"):
				if v, _ := m["country"].(string); v != "" {
					country = v
				}
				if v, _ := m["isp"].(string); v != "" {
					provider = v
				}
			default:
				if v, _ := m["countryCode"].(string); v != "" {
					country = v
				}
				if v, _ := m["isp"].(string); v != "" {
					provider = v
				}
				if v, _ := m["as"].(string); v != "" {
					asn = v
				}
			}
		}()
		if country != "" || provider != "" || asn != "" {
			break
		}
	}

	geoCache.Store(ip, GeoInfo{Country: country, Provider: provider, ASN: asn})
	return country, provider, asn
}

func calculateScore(result DNSResult) int {
	score := 0

	if result.Lookup {
		score += 20
		switch {
		case result.LookupMs < 20:
			score += 15
		case result.LookupMs < 50:
			score += 10
		case result.LookupMs < 100:
			score += 5
		}
	}

	if result.HTTPS {
		score += 20
		switch {
		case result.HTTPSMs < 50:
			score += 15
		case result.HTTPSMs < 200:
			score += 10
		case result.HTTPSMs < 500:
			score += 5
		}
	}

	if result.DNSSEC {
		score += 10
	}
	if result.EDNS {
		score += 5
	}
	if result.EDNSBuffer >= 1232 {
		score += 2
	}
	if result.IPv6 {
		score += 5
	}
	if result.UDP {
		score += 3
	}
	if result.TCP {
		score += 3
	}
	if result.DoT {
		score += 5
	}
	if result.DoH {
		score += 5
	}
	if result.HTTP2 {
		score += 3
	}
	if result.HTTPStatus >= 200 && result.HTTPStatus < 400 {
		score += 4
	}
	if result.HTTPBlocked {
		score -= 5
	}
	for _, ok := range result.Records {
		if ok {
			score += 1
		}
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

func sortResults(results []DNSResult, config Config) {
	sort.SliceStable(results, func(i, j int) bool {
		if config.Score {
			if results[i].Score != results[j].Score {
				return results[i].Score > results[j].Score
			}
		}
		if results[i].LookupMs != results[j].LookupMs {
			return results[i].LookupMs < results[j].LookupMs
		}
		return results[i].DNS < results[j].DNS
	})
}

func printTable(results []DNSResult, config Config) {
	green, yellow, red, reset := Green, Yellow, Red, Reset
	if config.NoColor {
		green, yellow, red, reset = "", "", "", ""
	}

	fmt.Printf("%-4s %-16s %-10s %-12s %-10s %-20s %-6s\n", "#", "DNS", "Lookup", "HTTPS", "Location", "Provider", "Score")
	fmt.Println(strings.Repeat("-", 85))

	limit := 20
	if len(results) < limit {
		limit = len(results)
	}
	for i := 0; i < limit; i++ {
		r := results[i]
		lookupStr := fmt.Sprintf("%dms", r.LookupMs)
		httpsStr := "-"
		if config.Mode >= 1 {
			if r.HTTPS {
				httpsStr = fmt.Sprintf("%dms", r.HTTPSMs)
			} else {
				httpsStr = "FAIL"
			}
		}
		location := r.Country
		if location == "" {
			location = "Unknown"
		}
		provider := r.Provider
		if provider == "" {
			provider = "-"
		}
		if len(provider) > 18 {
			provider = provider[:18] + ".."
		}
		scoreStr := "-"
		if config.Mode >= 1 || config.Score {
			scoreStr = fmt.Sprintf("%d", r.Score)
		}
		color := green
		if config.Mode >= 1 {
			switch {
			case r.Score >= 70:
				color = green
			case r.Score >= 50:
				color = yellow
			default:
				color = red
			}
		}
		fmt.Printf("%s%-4s %-16s %-10s %-12s %-10s %-20s %-6s%s\n", color, fmt.Sprintf("#%d", i+1), r.DNS, lookupStr, httpsStr, location, provider, scoreStr, reset)
	}
}

func printSummary(results []DNSResult, config Config) {
	if len(results) == 0 {
		fmt.Printf("\n%sNo valid DNS servers found%s\n", Red, Reset)
		return
	}

	sorted := make([]DNSResult, len(results))
	copy(sorted, results)
	sortResults(sorted, config)

	var totalLookup, totalHTTPS, totalScore int64
	for _, r := range results {
		if r.Lookup {
			totalLookup++
		}
		if r.HTTPS {
			totalHTTPS++
		}
		totalScore += int64(r.Score)
	}

	avgScore := int64(0)
	if len(results) > 0 {
		avgScore = totalScore / int64(len(results))
	}

	fmt.Printf("\n%s========================================%s\n", Green, Reset)
	fmt.Println("Git&Tg: github.com/batmanpriv")
	fmt.Printf("Total DNS Tested: %d\n", len(results))
	fmt.Printf("Valid DNS (Lookup OK): %d\n", totalLookup)
	if config.Mode >= 1 {
		fmt.Printf("HTTPS OK: %d\n", totalHTTPS)
		fmt.Printf("Average Score: %d/100\n", avgScore)
	} else if config.Score {
		fmt.Printf("Average Score: %d/100\n", avgScore)
	}
	fmt.Printf("Valid DNS saved to: valid_dns_%s.txt\n", time.Now().Format("20060102"))
	if len(sorted) > 0 {
		fmt.Printf("Fastest DNS: %s (%dms)\n", sorted[0].DNS, sorted[0].LookupMs)
		if config.Score || config.Mode >= 1 {
			fmt.Printf("Highest Score: %s (%d/100)\n", sorted[0].DNS, sorted[0].Score)
		}
	}
	fmt.Printf("========================================\n")
}

func printRecommendation(results []DNSResult, config Config) {
	if len(results) == 0 {
		return
	}

	sorted := make([]DNSResult, len(results))
	copy(sorted, results)
	sortResults(sorted, config)

	best := sorted[0]
	var secondary DNSResult
	if len(sorted) > 1 {
		secondary = sorted[1]
	}

	fmt.Printf("\n%s========================================%s\n", Green, Reset)
	fmt.Printf("%s RECOMMENDED DNS CONFIGURATION%s\n", Yellow, Reset)
	fmt.Printf("%s========================================%s\n", Green, Reset)

	fmt.Printf("\n%sPrimary:%s %s\n", White, Reset, best.DNS)
	if secondary.DNS != "" {
		fmt.Printf("%sSecondary:%s %s\n", White, Reset, secondary.DNS)
	}

	fmt.Printf("\n%sReason:%s\n", White, Reset)
	fmt.Printf(" • Latency: %dms\n", best.LookupMs)
	if best.HTTPS {
		fmt.Printf(" • HTTPS: %dms\n", best.HTTPSMs)
	}
	fmt.Printf(" • DNSSEC: %v\n", best.DNSSEC)
	fmt.Printf(" • DoH: %v\n", best.DoH)
	fmt.Printf(" • DoT: %v\n", best.DoT)
	fmt.Printf(" • IPv6: %v\n", best.IPv6)
	fmt.Printf(" • Score: %d/100\n", best.Score)

	fmt.Printf("\n%sTo apply this DNS automatically:%s\n", White, Reset)
	fmt.Printf(" ct dns apply-best\n")
	fmt.Printf("%s========================================%s\n", Green, Reset)
}

func uiLoop(config Config) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		<-ticker.C
		uiState.mu.Lock()
		if uiState.shouldQuit {
			uiState.mu.Unlock()
			return
		}
		results := make([]DNSResult, len(uiState.results))
		copy(results, uiState.results)
		completed := atomic.LoadInt32(&uiState.completed)
		total := uiState.total
		uiState.mu.Unlock()

		fmt.Print("\033[H\033[2J")
		fmt.Printf("DNS Benchmark - Testing %d servers\n\n", total)
		progress := 0.0
		if total > 0 {
			progress = float64(completed) / float64(total) * 100
		}
		fmt.Printf("Progress: %.1f%% (%d/%d) | Valid: %d\n\n", progress, completed, total, len(results))
		if len(results) > 0 {
			sortResults(results, config)
			printTable(results, config)
		} else {
			fmt.Println("Waiting for results...")
		}
	}
}

func findAndApplyBestDNS(config Config, registry map[string]ProviderEntry) string {
	dnsList := []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
		"9.9.9.9", "149.112.112.112", "94.140.14.14", "94.140.15.15",
		"76.76.19.19", "76.223.122.150", "45.90.28.0", "45.90.30.0",
	}

	domains := parseDomains(config.Domains, config.TestURL)
	results := make([]DNSResult, 0, len(dnsList))

	for _, dnsServer := range dnsList {
		r := testDNS(dnsServer, domains, config, registry)
		if r.Lookup {
			results = append(results, r)
		}
	}

	if len(results) == 0 {
		fmt.Println("No valid DNS found")
		return ""
	}

	sortResults(results, config)
	best := results[0]
	fmt.Printf("%sBest DNS: %s%s\n", Green, best.DNS, Reset)
	fmt.Printf(" Lookup: %dms\n", best.LookupMs)
	if best.HTTPS {
		fmt.Printf(" HTTPS: %dms\n", best.HTTPSMs)
	}
	fmt.Printf(" DNSSEC: %v\n", best.DNSSEC)
	fmt.Printf(" DoH: %v\n", best.DoH)
	fmt.Printf(" IPv6: %v\n", best.IPv6)
	fmt.Printf(" Score: %d/100\n\n", best.Score)

	setSystemDNS(best.DNS)
	return best.DNS
}

func parseDNSAddress(address string) (string, int) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", 53
	}
	if host, port, err := net.SplitHostPort(address); err == nil {
		p, err := strconv.Atoi(port)
		if err == nil {
			return host, p
		}
		return host, 53
	}
	if ip := net.ParseIP(address); ip != nil {
		return address, 53
	}
	if strings.Count(address, ":") == 1 {
		parts := strings.SplitN(address, ":", 2)
		if p, err := strconv.Atoi(parts[1]); err == nil {
			return parts[0], p
		}
	}
	return address, 53
}

func runProxyDownload(ctx *AppContext) error {
	fmt.Println("Downloading proxies...")
	return nil
}

func runProxyScrape(ctx *AppContext) error {
	fmt.Println("Scraping proxies...")
	return nil
}

func runProxyApplyBest(ctx *AppContext) error {
	fmt.Println("Applying best proxy...")
	return nil
}

func runXrayDownload(ctx *AppContext) error {
	fmt.Println("Downloading Xray configs...")
	return nil
}

func runMTProtoDownload(ctx *AppContext) error {
	fmt.Println("Downloading MTProto proxies...")
	return nil
}

func runProxyCheck(ctx *AppContext, args []string) error {
	file := ""
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		file = strings.TrimSpace(args[0])
	}
	if file == "" {
		p, err := smartPickFile(ctx, []string{"proxies.txt", "proxy.txt", "input.txt"}, "Proxy file")
		if err != nil {
			return err
		}
		file = p
	}
	fmt.Println("Proxy check file:", file)
	return nil
}

func runXrayTest(ctx *AppContext, args []string) error {
	file := ""
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		file = strings.TrimSpace(args[0])
	}
	if file == "" {
		p, err := smartPickFile(ctx, []string{"config.txt", "xray.txt", "input.txt"}, "Xray config file")
		if err != nil {
			return err
		}
		file = p
	}
	cfg := xp.CheckerConfig{
		ConfigFile: file,
		Download:   false,
		Limit:      0,
		Threads:    30,
		Timeout:    2,
		OutputFile: "alive_configs.txt",
	}
	_ = cfg
	xp.RunChecker(cfg)
	return nil
}

func runMTProtoCheck(ctx *AppContext, args []string) error {
	file := ""
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		file = strings.TrimSpace(args[0])
	}
	if file == "" {
		p, err := smartPickFile(ctx, []string{"mtproto.txt", "mtproto_proxies.txt", "input.txt"}, "MTProto file")
		if err != nil {
			return err
		}
		file = p
	}
	cfg := mtp.CheckerConfig{
		File:       file,
		Threads:    20,
		Timeout:    2 * time.Second,
		Download:   false,
		OutputFile: "valid_mtproto.txt",
		NoColor:    false,
	}
	checker := mtp.NewChecker(cfg)
	return checker.Run()
}

func runScraperOnly(outputDir string, workers int, skipTelegram bool) error {
	s := scraper.NewScraper(outputDir, workers, skipTelegram)
	if err := s.LoadConfig(); err != nil {
		fmt.Printf("%s[✗] Error loading config: %v%s\n", Red, err, Reset)
		return err
	}
	if err := s.Run(); err != nil {
		fmt.Printf("%s[✗] Error running scraper: %v%s\n", Red, err, Reset)
		return err
	}
	return nil
}

func addSource(url, sourceType string) error {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.LoadConfig(); err != nil {
		return err
	}
	return s.AddSource(url, sourceType)
}

func removeSource(url string) error {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.LoadConfig(); err != nil {
		return err
	}
	return s.RemoveSource(url)
}

func reloadScraperConfig() error {
	s := scraper.NewScraper("./output", 20, false)
	return s.ReloadConfig()
}

func showScraperConfig() error {
	s := scraper.NewScraper("./output", 20, false)
	return s.ShowConfig()
}

func isHelp(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "help", "-h", "--help":
		return true
	default:
		return false
	}
}

func cleanupResults(results []DNSResult) []DNSResult {
	out := make([]DNSResult, 0, len(results))
	for _, r := range results {
		if r.DNS != "" {
			out = append(out, r)
		}
	}
	return out
}

func cloneResults(results []DNSResult) []DNSResult {
	out := make([]DNSResult, len(results))
	copy(out, results)
	return out
}

func writeTextFile(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func readTextFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func ensureOutputDir(dir string) error {
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

type DNSMode int

const (
	DNSModeQuick DNSMode = iota
	DNSModeFull
)

func parseDomains(domains string, testURL string) []string {
	if strings.TrimSpace(testURL) != "" {
		return []string{strings.TrimSpace(testURL)}
	}
	parts := strings.Split(domains, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"cloudflare.com"}
	}
	return out
}

func runDNSApplyBest(ctx *AppContext, args []string) error {
	cfg := Config{
		Threads: 10,
		Mode:    0,
		Domains: "cloudflare.com,google.com,github.com",
	}
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		cfg.DNSFile = strings.TrimSpace(args[0])
	}
	registry := loadProviderRegistry(cfg.ProviderFile)
	best := findAndApplyBestDNS(cfg, registry)
	if best == "" {
		return errors.New("no valid dns found")
	}
	return nil
}

func testHTTP(domain string, provider ProviderEntry, timeout time.Duration, insecure bool, server string, redirects *int) HTTPResult {
	out := HTTPResult{}
	client := newReusableHTTPClient(server, provider, timeout, insecure, true, redirects)

	try := func(method string) (*http.Response, error) {
		var req *http.Request
		var err error
		if method == http.MethodGet {
			req, err = http.NewRequest(http.MethodGet, "https://"+domain, nil)
		} else {
			req, err = http.NewRequest(http.MethodHead, "https://"+domain, nil)
		}
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "ct-dns-checker/1.0")
		req.Header.Set("Accept", "*/*")
		req.Host = domain
		return client.Do(req)
	}

	start := time.Now()
	resp, err := try(http.MethodHead)
	if err != nil || resp == nil || resp.StatusCode >= 400 {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		resp, err = try(http.MethodGet)
	}
	out.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		out.Error = err
		return out
	}
	defer resp.Body.Close()

	out.Success = true
	out.Status = resp.StatusCode
	out.Blocked, out.Kind = classifyHTTPStatus(resp.StatusCode)
	out.FinalURL = resp.Request.URL.String()
	if redirects != nil {
		out.Redirects = *redirects
	}
	out.HTTP2 = resp.ProtoMajor == 2
	if resp.TLS != nil {
		out.TLSVersion = tlsVersionString(resp.TLS.Version)
		out.CipherSuite = tlsCipherSuiteString(resp.TLS.CipherSuite)
	}
	return out
}
