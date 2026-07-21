package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
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

	"github.com/batmanpriv/ct/pc"

	"github.com/miekg/dns"
)

type DNSResult struct {
	DNS         string          `json:"dns"`
	Lookup      bool            `json:"lookup"`
	LookupMs    int64           `json:"lookup_ms"`
	HTTPS       bool            `json:"https"`
	HTTPSMs     int64           `json:"https_ms"`
	Status      int             `json:"status"`
	TLSVersion  string          `json:"tls_version"`
	CipherSuite string          `json:"cipher_suite"`
	HTTP2       bool            `json:"http2"`
	Country     string          `json:"country"`
	ASN         string          `json:"asn"`
	Provider    string          `json:"provider"`
	Score       int             `json:"score"`
	Records     map[string]bool `json:"records"`
	DNSSEC      bool            `json:"dnssec"`
	EDNS        bool            `json:"edns"`
	EDNSBuffer  int             `json:"edns_buffer"`
	IPv6        bool            `json:"ipv6"`
	UDP         bool            `json:"udp"`
	TCP         bool            `json:"tcp"`
	DoT         bool            `json:"dot"`
	DoH         bool            `json:"doh"`
}

type Config struct {
	DNSFile     string
	Threads     int
	Domains     string
	Mode        int
	OutputJSON  bool
	Score       bool
	NoColor     bool
	SetDNS      string
	ApplyBest   bool
	Insecure    bool
	TestURL     string
}

var (
	cleanRegex = regexp.MustCompile(`[^0-9a-zA-Z\.\:\-\[\]]`)
	mu         sync.Mutex
	allResults []DNSResult
)

type UIState struct {
	results    []DNSResult
	total      int
	completed  int32
	mu         sync.Mutex
	shouldQuit bool
}

var uiState = &UIState{}

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
		best := findAndApplyBestDNS(config)
		if best != "" {
			fmt.Printf("\n✓ Best DNS (%s) applied to system\n", best)
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
		config.Domains = "cloudflare.com"
	}

	var domains []string
	if config.TestURL != "" {
		domains = []string{config.TestURL}
	} else {
		domains = strings.Split(config.Domains, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
	}

	f, err := os.Open(config.DNSFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var dnsList []string
	for scanner.Scan() {
		line := cleanRegex.ReplaceAllString(scanner.Text(), "")
		line = strings.TrimSpace(line)
		if line != "" {
			dnsList = append(dnsList, line)
		}
	}

	if len(dnsList) == 0 {
		fmt.Println("No valid DNS servers found")
		return
	}

	uiState.total = len(dnsList)

	go uiLoop(config)

	jobs := make(chan string, len(dnsList))
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dns := range jobs {
				result := testDNS(dns, domains, config)
				if result.Lookup {
					uiState.mu.Lock()
					uiState.results = append(uiState.results, result)
					uiState.mu.Unlock()
					saveValidDNS(dns)
				}
				atomic.AddInt32(&uiState.completed, 1)
			}
		}()
	}

	for _, dns := range dnsList {
		jobs <- dns
	}
	close(jobs)
	wg.Wait()

	uiState.mu.Lock()
	uiState.shouldQuit = true
	uiState.mu.Unlock()

	time.Sleep(500 * time.Millisecond)

	if config.OutputJSON {
		saveJSON(uiState.results)
	}

	printSummary(uiState.results, config)
	printRecommendation(uiState.results, config)
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
		uiState.mu.Unlock()

		fmt.Print("\033[H\033[2J")
		fmt.Printf("DNS Benchmark - Testing %d servers\n\n", uiState.total)

		progress := float64(completed) / float64(uiState.total) * 100
		fmt.Printf("Progress: %.1f%% (%d/%d) | Valid: %d\n\n",
			progress, completed, uiState.total, len(results))

		if len(results) > 0 {
			sortResults(results, config)
			printTable(results, config)
		} else {
			fmt.Println("Waiting for results...")
		}
	}
}

func sortResults(results []DNSResult, config Config) {
	sort.Slice(results, func(i, j int) bool {
		if config.Score && config.Mode >= 1 {
			if results[i].Score != results[j].Score {
				return results[i].Score > results[j].Score
			}
			return results[i].LookupMs < results[j].LookupMs
		}
		return results[i].LookupMs < results[j].LookupMs
	})
}

func printTable(results []DNSResult, config Config) {
	green := "\033[32m"
	yellow := "\033[33m"
	red := "\033[31m"
	reset := "\033[0m"

	if config.NoColor {
		green = ""
		yellow = ""
		red = ""
		reset = ""
	}

	fmt.Printf("%-4s %-16s %-10s %-12s %-10s %-20s %-6s\n",
		"#", "DNS", "Lookup", "HTTPS", "Location", "Provider", "Score")
	fmt.Println(strings.Repeat("-", 85))

	for i, result := range results {
		if i >= 20 {
			break
		}

		lookupStr := fmt.Sprintf("%dms", result.LookupMs)
		httpsStr := "-"
		if config.Mode >= 1 {
			if result.HTTPS {
				httpsStr = fmt.Sprintf("%dms", result.HTTPSMs)
			} else {
				httpsStr = "FAIL"
			}
		}

		location := result.Country
		if location == "" {
			location = "Unknown"
		}

		provider := result.Provider
		if len(provider) > 18 {
			provider = provider[:18] + ".."
		}
		if provider == "" {
			provider = "-"
		}

		scoreStr := "-"
		if config.Mode >= 1 {
			scoreStr = fmt.Sprintf("%d", result.Score)
		}

		color := green
		if config.Mode >= 1 {
			if result.Score >= 70 {
				color = green
			} else if result.Score >= 50 {
				color = yellow
			} else {
				color = red
			}
		}

		rank := fmt.Sprintf("#%d", i+1)
		fmt.Printf("%s%-4s %-16s %-10s %-12s %-10s %-20s %-6s%s\n",
			color, rank, result.DNS, lookupStr, httpsStr, location, provider, scoreStr, reset)
	}
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

	flag.Parse()

	config.TestURL = testURL

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

		if *proxyFile != "" || *proxyDownload || *proxyScrape || *proxyApplyBest {
			os.Exit(0)
		}
	}

	return config
}

func findAndApplyBestDNS(config Config) string {
	dnsList := []string{
		"1.1.1.1", "1.0.0.1",
		"8.8.8.8", "8.8.4.4",
		"9.9.9.9", "149.112.112.112",
		"208.67.222.222", "208.67.220.220",
		"94.140.14.14", "94.140.15.15",
		"76.76.19.19", "76.223.122.150",
	}

	var domains []string
	if config.TestURL != "" {
		domains = []string{config.TestURL}
	} else {
		domains = strings.Split(config.Domains, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
	}

	fmt.Printf("Finding best DNS among %d servers...\n\n", len(dnsList))

	var results []DNSResult
	var wg sync.WaitGroup
	jobs := make(chan string, len(dnsList))
	resultsMu := sync.Mutex{}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dns := range jobs {
				result := testDNS(dns, domains, config)
				resultsMu.Lock()
				if result.Lookup {
					results = append(results, result)
				}
				resultsMu.Unlock()
			}
		}()
	}

	for _, dns := range dnsList {
		jobs <- dns
	}
	close(jobs)
	wg.Wait()

	if len(results) == 0 {
		fmt.Println("No valid DNS found")
		return ""
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].LookupMs < results[j].LookupMs
	})

	best := results[0]

	fmt.Printf("Best DNS: %s\n", best.DNS)
	fmt.Printf("  Lookup: %dms\n", best.LookupMs)
	if best.HTTPS {
		fmt.Printf("  HTTPS: %dms\n", best.HTTPSMs)
	}
	fmt.Printf("  DNSSEC: %v\n", best.DNSSEC)
	fmt.Printf("  DoH: %v\n", best.DoH)
	fmt.Printf("  IPv6: %v\n", best.IPv6)
	fmt.Printf("  Score: %d/100\n\n", best.Score)

	setSystemDNS(best.DNS)
	return best.DNS
}

func printRecommendation(results []DNSResult, config Config) {
	if len(results) == 0 {
		return
	}

	sorted := make([]DNSResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score
		}
		return sorted[i].LookupMs < sorted[j].LookupMs
	})

	best := sorted[0]
	var secondary DNSResult
	if len(sorted) > 1 {
		secondary = sorted[1]
	}

	fmt.Printf("\n%s========================================%s\n", "\033[32m", "\033[0m")
	fmt.Printf("%s      RECOMMENDED DNS CONFIGURATION%s\n", "\033[33m", "\033[0m")
	fmt.Printf("%s========================================%s\n", "\033[32m", "\033[0m")

	fmt.Printf("\nPrimary:   %s\n", best.DNS)
	if secondary.DNS != "" {
		fmt.Printf("Secondary: %s\n", secondary.DNS)
	}

	fmt.Printf("\nReason:\n")
	fmt.Printf("  • Latency: %dms (Excellent)\n", best.LookupMs)
	if best.HTTPS {
		fmt.Printf("  • HTTPS: %dms\n", best.HTTPSMs)
	}
	fmt.Printf("  • DNSSEC: %v\n", best.DNSSEC)
	fmt.Printf("  • DoH: %v\n", best.DoH)
	fmt.Printf("  • IPv6: %v\n", best.IPv6)
	fmt.Printf("  • Score: %d/100\n", best.Score)

	fmt.Printf("\nTo apply this DNS automatically:\n")
	fmt.Printf("  ct.exe -apply-best\n")

	fmt.Printf("%s========================================%s\n", "\033[32m", "\033[0m")
}

func setSystemDNS(dns string) {
	fmt.Printf("\nSetting system DNS to: %s\n", dns)
	fmt.Println(strings.Repeat("-", 40))

	if runtime.GOOS == "windows" {
		cmd := exec.Command("net", "session")
		if err := cmd.Run(); err != nil {
			fmt.Println("⚠️ You need to run as Administrator!")
			return
		}
	}

	switch runtime.GOOS {
	case "windows":
		setWindowsDNS(dns)
	case "linux":
		setLinuxDNS(dns)
	case "darwin":
		setMacDNS(dns)
	default:
		fmt.Printf("Unsupported OS: %s\n", runtime.GOOS)
	}
}

func setWindowsDNS(dns string) {
	interfaces := []string{"Wi-Fi", "Ethernet", "Ethernet 2"}
	var iface string

	for _, name := range interfaces {
		cmd := exec.Command("powershell", "-Command",
			fmt.Sprintf(`Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Name -eq "%s"} | Select-Object -First 1 | ForEach-Object { $_.InterfaceIndex }`, name))
		output, err := cmd.Output()
		if err == nil {
			iface = strings.TrimSpace(string(output))
			if iface != "" {
				break
			}
		}
	}

	if iface == "" {
		cmd := exec.Command("powershell", "-Command",
			`Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1 | ForEach-Object { $_.InterfaceIndex }`)
		output, err := cmd.Output()
		if err != nil {
			fmt.Println("Error finding network interface:", err)
			return
		}
		iface = strings.TrimSpace(string(output))
	}

	if iface == "" {
		fmt.Println("No active network interface found")
		return
	}

	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dns", iface, "dhcp")
	cmd.Run()

	cmd = exec.Command("netsh", "interface", "ipv4", "set", "dns", iface, "static", dns, "primary")
	if err := cmd.Run(); err != nil {
		fmt.Println("Error setting DNS:", err)
		return
	}

	fmt.Printf("✓ DNS set to %s (Interface: %s)\n", dns, iface)
	exec.Command("ipconfig", "/flushdns").Run()
}

func setLinuxDNS(dns string) {
	cmd := exec.Command("systemd-resolve", "--set-dns="+dns, "--interface=eth0")
	if err := cmd.Run(); err == nil {
		fmt.Printf("✓ DNS set to %s using systemd-resolved\n", dns)
		return
	}

	resolvConf := fmt.Sprintf("nameserver %s\n", dns)
	cmd = exec.Command("sh", "-c", "echo '"+resolvConf+"' | sudo tee /etc/resolv.conf > /dev/null")
	if err := cmd.Run(); err != nil {
		fmt.Println("Error setting DNS. Try running with sudo:", err)
		return
	}
	fmt.Printf("✓ DNS set to %s in /etc/resolv.conf\n", dns)
}

func setMacDNS(dns string) {
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

	cmd = exec.Command("networksetup", "-setdnsservers", service, dns)
	if err := cmd.Run(); err != nil {
		fmt.Println("Error setting DNS:", err)
		return
	}
	fmt.Printf("✓ DNS set to %s (Service: %s)\n", dns, service)
}

func checkDNSStatus() {
	fmt.Println("\nCurrent DNS Settings:")
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
		cmd := exec.Command("networksetup", "-getdnsservers", "Wi-Fi")
		output, _ := cmd.Output()
		fmt.Printf("Wi-Fi DNS:\n%s\n", string(output))
		cmd = exec.Command("networksetup", "-getdnsservers", "Ethernet")
		output, _ = cmd.Output()
		fmt.Printf("Ethernet DNS:\n%s\n", string(output))
	default:
		fmt.Printf("Unsupported OS: %s\n", runtime.GOOS)
	}
}

func testDNS(dnsServer string, domains []string, config Config) DNSResult {
	result := DNSResult{
		DNS:     dnsServer,
		Records: make(map[string]bool),
	}

	serverAddr, port := parseDNSAddress(dnsServer)

	start := time.Now()
	ips, err := dnsLookup(serverAddr, port, domains[0], dns.TypeA)
	lookupTime := time.Since(start).Milliseconds()

	if err != nil || len(ips) == 0 {
		return result
	}

	result.Lookup = true
	result.LookupMs = lookupTime
	ip := ips[0]

	if config.Mode >= 1 {
		result.UDP = testUDP(serverAddr, port)
		result.TCP = testTCP(serverAddr, port, domains[0])
		result.DNSSEC = testDNSSEC(serverAddr, port, domains[0])
		result.EDNS, result.EDNSBuffer = testEDNS(serverAddr, port, domains[0])
		result.IPv6 = testIPv6(serverAddr, port)

		recordTypes := []struct {
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
		}

		for _, domain := range domains[:1] {
			for _, rt := range recordTypes {
				if _, err := dnsLookup(serverAddr, port, domain, rt.qtype); err == nil {
					result.Records[rt.name] = true
				}
			}
		}

		httpStart := time.Now()
		httpResult := testHTTP(ip, domains[0])
		httpTime := time.Since(httpStart).Milliseconds()

		if httpResult.success {
			result.HTTPS = true
			result.HTTPSMs = httpTime
			result.Status = httpResult.status
			result.TLSVersion = httpResult.tlsVersion
			result.CipherSuite = httpResult.cipherSuite
			result.HTTP2 = httpResult.http2
		} else {
			result.HTTPS = false
			result.HTTPSMs = -1
		}

		result.DoT = testDoT(serverAddr, domains[0], config)
		result.DoH = testDoH(serverAddr, domains[0])

		result.Score = calculateScore(result)
	}

	result.Country, result.Provider = getGeoIP(ip)

	return result
}

func parseDNSAddress(address string) (string, int) {
	if strings.HasPrefix(address, "[") && strings.Contains(address, "]") {
		host, port, err := net.SplitHostPort(address)
		if err == nil {
			p, _ := strconv.Atoi(port)
			return host, p
		}
	}

	if strings.Contains(address, ":") {
		parts := strings.Split(address, ":")
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil {
				return parts[0], port
			}
		}
		if net.ParseIP(address) != nil {
			return address, 53
		}
	}

	return address, 53
}

func dnsLookup(dnsServer string, port int, domain string, qtype uint16) ([]string, error) {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		m.SetEdns0(4096, true)
	}

	r, _, err := c.Exchange(m, fmt.Sprintf("%s:%d", dnsServer, port))
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: %d", r.Rcode)
	}

	var ips []string
	for _, ans := range r.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ips = append(ips, a.A.String())
		case *dns.AAAA:
			ips = append(ips, a.AAAA.String())
		case *dns.MX:
			ips = append(ips, fmt.Sprintf("%s (priority %d)", a.Mx, a.Preference))
		case *dns.TXT:
			ips = append(ips, strings.Join(a.Txt, " "))
		case *dns.CNAME:
			ips = append(ips, a.Target)
		case *dns.NS:
			ips = append(ips, a.Ns)
		case *dns.SOA:
			ips = append(ips, fmt.Sprintf("%s %s %d %d %d %d %d",
				a.Ns, a.Mbox, a.Serial, a.Refresh, a.Retry, a.Expire, a.Minttl))
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no records found")
	}

	return ips, nil
}

func testDNSSEC(dnsServer string, port int, domain string) bool {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetDo()
	opt.SetUDPSize(4096)
	m.Extra = append(m.Extra, opt)

	r, _, err := c.Exchange(m, fmt.Sprintf("%s:%d", dnsServer, port))
	if err != nil {
		return false
	}

	if r.Rcode != dns.RcodeSuccess {
		return false
	}

	for _, ans := range r.Answer {
		if ans.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}
	for _, ans := range r.Ns {
		if ans.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}

	return false
}

func testEDNS(dnsServer string, port int, domain string) (bool, int) {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	m.SetEdns0(4096, false)

	r, _, err := c.Exchange(m, fmt.Sprintf("%s:%d", dnsServer, port))
	if err != nil {
		return false, 0
	}

	for _, extra := range r.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			opt := extra.(*dns.OPT)
			bufferSize := int(opt.Hdr.Class)
			return true, bufferSize
		}
	}

	return false, 0
}

func testUDP(dnsServer string, port int) bool {
	c := new(dns.Client)
	c.Timeout = 1 * time.Second
	c.Net = "udp"

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	m.RecursionDesired = true

	_, _, err := c.Exchange(m, fmt.Sprintf("%s:%d", dnsServer, port))
	return err == nil
}

func testTCP(dnsServer string, port int, domain string) bool {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	c.Net = "tcp"

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	_, _, err := c.Exchange(m, fmt.Sprintf("%s:%d", dnsServer, port))
	return err == nil
}

func testDoT(dnsServer, domain string, config Config) bool {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	c.Net = "tcp-tls"
	c.TLSConfig = &tls.Config{
		ServerName:         dnsServer,
		InsecureSkipVerify: config.Insecure,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	_, _, err := c.Exchange(m, fmt.Sprintf("%s:853", dnsServer))
	return err == nil
}

func testDoH(dnsServer, domain string) bool {
	knownDoH := map[string]string{
		"1.1.1.1":         "cloudflare-dns.com",
		"1.0.0.1":         "cloudflare-dns.com",
		"8.8.8.8":         "dns.google",
		"8.8.4.4":         "dns.google",
		"9.9.9.9":         "dns.quad9.net",
		"149.112.112.112": "dns.quad9.net",
	}

	host, ok := knownDoH[dnsServer]
	if !ok {
		return false
	}

	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("https://%s/dns-query?name=%s&type=A", host, domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func testIPv6(dnsServer string, port int) bool {
	_, err := dnsLookup(dnsServer, port, "google.com", dns.TypeAAAA)
	return err == nil
}

func getGeoIP(ip string) (string, string) {
	cacheKey := ip
	if val, ok := geoCache.Load(cacheKey); ok {
		if info, ok := val.(GeoInfo); ok {
			return info.Country, info.Provider
		}
	}

	var country, provider string
	apis := []string{
		"http://ip-api.com/json/%s?fields=countryCode,isp",
		"https://ipwhois.app/json/%s",
		"https://ipinfo.io/%s/json",
	}

	for _, api := range apis {
		client := &http.Client{Timeout: 2 * time.Second}
		url := fmt.Sprintf(api, ip)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			continue
		}

		if strings.Contains(api, "ip-api") {
			country, _ = data["countryCode"].(string)
			provider, _ = data["isp"].(string)
		} else if strings.Contains(api, "ipwhois") {
			country, _ = data["country"].(string)
			provider, _ = data["isp"].(string)
		} else if strings.Contains(api, "ipinfo") {
			country, _ = data["country"].(string)
			provider, _ = data["org"].(string)
		}

		if country != "" || provider != "" {
			break
		}
	}

	geoCache.Store(cacheKey, GeoInfo{Country: country, Provider: provider})

	return country, provider
}

type GeoInfo struct {
	Country  string
	Provider string
}

var geoCache sync.Map

type HTTPResult struct {
	success     bool
	status      int
	tlsVersion  string
	cipherSuite string
	http2       bool
}

func testHTTP(ip, domain string) HTTPResult {
	result := HTTPResult{success: false}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
			},
			TLSClientConfig: &tls.Config{
				ServerName: domain,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		return result
	}
	req.Host = domain

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.success = true
	result.status = resp.StatusCode

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		result.tlsVersion = tlsVersionString(resp.TLS.Version)
		result.cipherSuite = tlsCipherSuiteString(resp.TLS.CipherSuite)
	}

	if resp.ProtoMajor == 2 {
		result.http2 = true
	}

	return result
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return "TLS1.0/1.1"
	}
}

func tlsCipherSuiteString(cipher uint16) string {
	switch cipher {
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("0x%x", cipher)
	}
}

func calculateScore(result DNSResult) int {
	score := 0

	if result.Lookup {
		score += 20
		if result.LookupMs < 10 {
			score += 15
		} else if result.LookupMs < 50 {
			score += 10
		} else if result.LookupMs < 100 {
			score += 5
		}
	}

	if result.HTTPS {
		score += 20
		if result.HTTPSMs < 50 {
			score += 15
		} else if result.HTTPSMs < 200 {
			score += 10
		} else if result.HTTPSMs < 500 {
			score += 5
		}
	}

	if result.DNSSEC {
		score += 10
	}

	if result.EDNS {
		score += 5
	}

	if result.IPv6 {
		score += 5
	}

	if result.UDP && result.TCP {
		score += 5
	}

	if result.DoT || result.DoH {
		score += 5
	}

	for _, v := range result.Records {
		if v {
			score += 2
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}

func saveValidDNS(dns string) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile("valid_dns_"+time.Now().Format("20060102")+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString(dns + "\n")
}

func saveJSON(results []DNSResult) {
	file, err := os.Create("results.json")
	if err != nil {
		fmt.Println("Error creating JSON:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(results)
	fmt.Println("\nResults saved to results.json")
}

func printSummary(results []DNSResult, config Config) {
	if len(results) == 0 {
		fmt.Println("\nNo valid DNS servers found")
		return
	}

	sorted := make([]DNSResult, len(results))
	copy(sorted, results)
	sortResults(sorted, config)

	var totalLookup int64
	var totalHTTPS int64
	var totalScore int64

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
	if len(results) > 0 && config.Mode >= 1 {
		avgScore = totalScore / int64(len(results))
	}

	fmt.Printf("\n%s========================================%s\n", "\033[32m", "\033[0m")
  fmt.Println("Git&Tg: github.com/batmanpriv")
	fmt.Printf("Total DNS Tested: %d\n", len(results))
	fmt.Printf("Valid DNS (Lookup OK): %d\n", totalLookup)
	if config.Mode >= 1 {
		fmt.Printf("HTTPS OK: %d\n", totalHTTPS)
		fmt.Printf("Average Score: %d/100\n", avgScore)
	}
	fmt.Printf("Valid DNS saved to: valid_dns_%s.txt\n", time.Now().Format("20060102"))

	if len(sorted) > 0 {
		fmt.Printf("Fastest DNS: %s (%dms)\n", sorted[0].DNS, sorted[0].LookupMs)
		if config.Mode >= 1 && config.Score {
			fmt.Printf("Highest Score: %s (%d/100)\n", sorted[0].DNS, sorted[0].Score)
		}
	}
	fmt.Printf("========================================\n")
}
