package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
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

type DNSResult struct {
	DNS         string            `json:"dns"`
	Lookup      bool              `json:"lookup"`
	LookupMs    int64             `json:"lookup_ms"`
	UDP         bool              `json:"udp"`
	TCP         bool              `json:"tcp"`
	DNSSEC      bool              `json:"dnssec"`
	EDNS        bool              `json:"edns"`
	EDNSBuffer  int               `json:"edns_buffer"`
	IPv6        bool              `json:"ipv6"`
	HTTPS       bool              `json:"https"`
	HTTPSMs     int64             `json:"https_ms"`
	HTTPStatus  int               `json:"http_status"`
	HTTPBlocked  bool              `json:"http_blocked"`
	HTTPKind    string            `json:"http_kind"`
	HTTPError   string            `json:"http_error"`
	Redirects   int               `json:"redirects"`
	TLSVersion  string            `json:"tls_version"`
	CipherSuite string            `json:"cipher_suite"`
	HTTP2       bool              `json:"http2"`
	DoT         bool              `json:"dot"`
	DoH         bool              `json:"doh"`
	DoTError    string            `json:"dot_error"`
	DoHError    string            `json:"doh_error"`
	Country     string            `json:"country"`
	ASN         string            `json:"asn"`
	Provider    string            `json:"provider"`
	Score       int               `json:"score"`
	Records     map[string]bool   `json:"records"`
	LookupError string            `json:"lookup_error"`
	Extra       map[string]string `json:"extra"`
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
	cleanRegex = regexp.MustCompile(`[^0-9a-zA-Z\.\:\-\[\]]`)
	uiState    = &UIState{}
	geoCache   sync.Map
	provCache  sync.Map
	mu         sync.Mutex
)

func main() {
	config := parseFlags()

	if config.SetDNS != "" {
		if config.SetDNS == "status" {
			checkDNSStatus()
			return
		}
		setSystemDNS(config.SetDNS)
		return
	}

	if config.ApplyBest {
		registry := loadProviderRegistry(config.ProviderFile)
		best := findAndApplyBestDNS(config, registry)
		if best != "" {
			fmt.Printf("\n%s✓ Best DNS (%s) applied to system%s\n", Green, best, Reset)
		}
		return
	}

	if config.DNSFile == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("DNS file path: ")
		dnsPath, _ := reader.ReadString('\n')
		config.DNSFile = strings.TrimSpace(dnsPath)
	}

	if config.Threads < 2 {
		config.Threads = 2
	}

	if config.Domains == "" && config.TestURL == "" {
		config.Domains = "cloudflare.com,google.com,github.com"
	}

	domains := parseDomains(config.Domains, config.TestURL)

	dnsList, err := loadDNSList(config.DNSFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	if len(dnsList) == 0 {
		fmt.Println("No valid DNS servers found")
		return
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
}

func parseFlags() Config {
	config := Config{}
	testURL := ""

	flag.StringVar(&config.DNSFile, "dns", "", "DNS file path")
	flag.IntVar(&config.Threads, "t", 10, "Number of threads")
	flag.StringVar(&config.Domains, "domains", "cloudflare.com", "Domains to test (comma separated)")
	flag.StringVar(&testURL, "url", "", "Test URL for HTTP check")
	flag.IntVar(&config.Mode, "mode", 0, "0: DNS only, 1: DNS + HTTP")
	flag.BoolVar(&config.OutputJSON, "json", false, "Output in JSON format")
	flag.BoolVar(&config.Score, "score", false, "Sort by score instead of speed")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")
	flag.StringVar(&config.SetDNS, "set", "", "Set system DNS (e.g. -set 1.1.1.1 or -set status)")
	flag.BoolVar(&config.ApplyBest, "apply-best", false, "Find best DNS and apply to system")
	flag.BoolVar(&config.Insecure, "insecure", false, "Allow insecure TLS for DoT")
	flag.StringVar(&config.ProviderFile, "providers", "", "Custom providers json file")

	proxyFile := flag.String("proxy", "", "Proxy file path")
	proxyThreads := flag.Int("proxy-t", 50, "Proxy threads")
	proxyTypes := flag.String("proxy-types", "", "Proxy types")
	proxyAuto := flag.Bool("proxy-auto", true, "Auto detect proxy type")
	proxyDownload := flag.Bool("proxy-dl", false, "Download proxies")
	proxyScrape := flag.Bool("proxy-scrape", false, "Scrape proxies")
	proxyScore := flag.Bool("proxy-score", false, "Sort by score")
	proxyApplyBest := flag.Bool("proxy-apply-best", false, "Apply best proxy")
	proxySet := flag.String("proxy-set", "", "Set system proxy")
	proxyTestURL := flag.String("proxy-url", "http://httpbin.org/ip", "Test URL for proxy")

	xrayFile := flag.String("xray-file", "", "Xray config file path")
	xrayDownload := flag.Bool("xray-dl", false, "Download xray configs")
	xrayLimit := flag.Int("xray-limit", 0, "Limit number of xray configs")
	xrayThreads := flag.Int("xray-threads", 30, "Xray test threads")
	xrayTimeout := flag.Float64("xray-timeout", 2, "Xray test timeout in seconds")
	xrayAddSource := flag.String("xray-add-source", "", "Add new xray source URL")
	xrayTestURL := flag.String("xray-url", "", "Test URL for xray HTTP check")
	xrayOutput := flag.String("xray-output", "alive_configs.txt", "Output file for alive xray configs")

	mtprotoFile := flag.String("mtproto", "", "MTProto proxy file path")
	mtprotoDownload := flag.Bool("mtproto-dl", false, "Download MTProto proxies from GitHub")
	mtprotoThreads := flag.Int("mtproto-t", 20, "Number of threads for MTProto checking")
	mtprotoTimeout := flag.Int("mtproto-timeout", 2, "Timeout in seconds for MTProto checking")
	mtprotoOutput := flag.String("mtproto-out", "valid_mtproto.txt", "Output file for healthy MTProto proxies")
	mtprotoNoColor := flag.Bool("mtproto-no-color", false, "Disable colored output for MTProto")

	sourceURL := flag.String("source", "", "Add source URL with auto-detection")
	sourceType := flag.String("source-type", "", "Force source type")
	scrapeOnly := flag.Bool("scrape-only", false, "Run only scraper and exit")
	outputDir := flag.String("output", "./output", "Output directory for scraped data")
	workers := flag.Int("workers", 20, "Number of concurrent workers for scraping")
	skipTelegram := flag.Bool("skip-telegram", false, "Skip Telegram scraping")
	removeURL := flag.String("remove-url", "", "Remove a URL from config")
	reloadConfig := flag.Bool("reload", false, "Reload config")
	showConfig := flag.Bool("show-config", false, "Show saved config file path and contents")

	flag.Parse()
	config.TestURL = testURL

	if *xrayFile != "" || *xrayDownload || *xrayAddSource != "" {
		xrayConfig := xp.CheckerConfig{
			ConfigFile: *xrayFile,
			Download:   *xrayDownload,
			Limit:      *xrayLimit,
			Threads:    *xrayThreads,
			Timeout:    *xrayTimeout,
			AddSource:  *xrayAddSource,
			TestURL:    *xrayTestURL,
			NoColor:    false,
			OutputFile: *xrayOutput,
		}
		xp.RunChecker(xrayConfig)
		os.Exit(0)
	}

	if *mtprotoFile != "" || *mtprotoDownload {
		mtpConfig := mtp.CheckerConfig{
			File:       *mtprotoFile,
			Threads:    *mtprotoThreads,
			Timeout:    time.Duration(*mtprotoTimeout) * time.Second,
			Download:   *mtprotoDownload,
			OutputFile: *mtprotoOutput,
			NoColor:    *mtprotoNoColor,
		}
		checker := mtp.NewChecker(mtpConfig)
		if err := checker.Run(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *scrapeOnly {
		runScraperOnly(*outputDir, *workers, *skipTelegram)
		os.Exit(0)
	}

	if *sourceURL != "" {
		addSource(*sourceURL, *sourceType)
		os.Exit(0)
	}

	if *removeURL != "" {
		removeSource(*removeURL)
		os.Exit(0)
	}

	if *reloadConfig {
		reloadScraperConfig()
		os.Exit(0)
	}

	if *showConfig {
		showScraperConfig()
		os.Exit(0)
	}

	if *proxyFile != "" || *proxyDownload || *proxyScrape || *proxyApplyBest || *proxySet != "" {
		pcConfig := pc.Config{
			ProxyFile:  *proxyFile,
			Threads:    *proxyThreads,
			Types:      *proxyTypes,
			AutoDetect: *proxyAuto,
			Download:   *proxyDownload,
			Scrape:     *proxyScrape,
			Score:      *proxyScore,
			ApplyBest:  *proxyApplyBest,
			SetProxy:   *proxySet,
			TestURL:    *proxyTestURL,
			Timeout:    3,
			OutputJSON: false,
			NoColor:    false,
		}
		pc.RunProxyChecker(pcConfig)
		os.Exit(0)
	}

	return config
}

func parseDomains(domains string, testURL string) []string {
	if testURL != "" {
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
		out = []string{"cloudflare.com"}
	}
	return out
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
		line := strings.TrimSpace(cleanRegex.ReplaceAllString(scanner.Text(), ""))
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
	cacheKey := server
	if v, ok := provCache.Load(cacheKey); ok {
		if p, ok := v.(ProviderEntry); ok {
			return p
		}
	}
	if p, ok := registry[server]; ok {
		provCache.Store(cacheKey, p)
		return p
	}
	p := ProviderEntry{
		Name: "Unknown",
		DoH:  "",
		DoT:  net.JoinHostPort(server, "853"),
		SNI:  server,
		Host: server,
	}
	provCache.Store(cacheKey, p)
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

func runScraperOnly(outputDir string, workers int, skipTelegram bool) {
	s := scraper.NewScraper(outputDir, workers, skipTelegram)
	if err := s.LoadConfig(); err != nil {
		fmt.Printf("%s[✗] Error loading config: %v%s\n", Red, err, Reset)
		return
	}
	if err := s.Run(); err != nil {
		fmt.Printf("%s[✗] Error running scraper: %v%s\n", Red, err, Reset)
		return
	}
}

func addSource(url, sourceType string) {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.LoadConfig(); err != nil {
		fmt.Printf("%s[✗] Error loading config: %v%s\n", Red, err, Reset)
		return
	}
	fmt.Printf("%s[ℹ] Adding source: %s%s\n", Blue, url, Reset)
	if err := s.AddSource(url, sourceType); err != nil {
		fmt.Printf("%s[✗] Error adding source: %v%s\n", Red, err, Reset)
		return
	}
	fmt.Printf("%s[✓] Source added successfully!%s\n", Green, Reset)
	fmt.Printf("%s[ℹ] Run without flags to scrape all sources%s\n", Blue, Reset)
}

func showScraperConfig() {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.ShowConfig(); err != nil {
		fmt.Printf("%s[✗] Error showing config: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}
}

func removeSource(url string) {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.RemoveSource(url); err != nil {
		fmt.Printf("%s[✗] Error removing source: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}
	fmt.Printf("%s[✓] Source removed successfully: %s%s\n", Green, url, Reset)
}

func reloadScraperConfig() {
	s := scraper.NewScraper("./output", 20, false)
	if err := s.ReloadConfig(); err != nil {
		fmt.Printf("%s[✗] Error reloading config: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}
	fmt.Printf("%s[✓] Config reloaded successfully%s\n", Green, Reset)
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

	if result.Extra == nil {
		result.Extra = map[string]string{}
	}

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

var (
	httpClientCache sync.Map
	dohClientCache  sync.Map
)

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
		ForceAttemptHTTP2:     true,
		MaxIdleConns:           50,
		MaxIdleConnsPerHost:    10,
		IdleConnTimeout:        60 * time.Second,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:   1 * time.Second,
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
	fmt.Printf(" ct.exe -apply-best\n")
	fmt.Printf("%s========================================%s\n", Green, Reset)
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
