package pc

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

	"golang.org/x/net/proxy"
)

type ProxyResult struct {
	Proxy     string `json:"proxy"`
	Type      string `json:"type"`
	Working   bool   `json:"working"`
	LatencyMs int64  `json:"latency_ms"`
	Country   string `json:"country"`
	Provider  string `json:"provider"`
	Anonymity string `json:"anonymity"`
	Speed     string `json:"speed"`
	Score     int    `json:"score"`
	CheckTime string `json:"check_time"`
	Error     string `json:"error,omitempty"`
	IPv6      bool   `json:"ipv6"`
	HasAuth   bool   `json:"has_auth"`
}

type Config struct {
	ProxyFile  string
	Threads    int
	TestURL    string
	Timeout    int
	OutputJSON bool
	Score      bool
	NoColor    bool
	Types      string
	SetProxy   string
	ApplyBest  bool
	AutoDetect bool
	Download   bool
	Scrape     bool
	ScrapeDeep bool
	ProxyType  string
	Insecure   bool
	Sources    string
}

type GeoInfo struct {
	Country  string
	Provider string
}

type UIState struct {
	results    []ProxyResult
	total      int
	completed  int32
	mu         sync.RWMutex
	shouldQuit bool
}

var (
	uiState        UIState
	allResults     []ProxyResult
	allResultsMu   sync.Mutex
	geoCache       = map[string]GeoInfo{}
	geoCacheMu     sync.Mutex
	anonymityCache = map[string]string{}
	anonymityMu    sync.Mutex
	validProxyMu   sync.Mutex
	totalProxies   int

	proxyRegex = regexp.MustCompile(`(?:socks5|socks4|https?):\/\/[^\s]+|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b`)
	ipRegex    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	ipv6Regex  = regexp.MustCompile(`\b[0-9a-fA-F:]+:[0-9a-fA-F:]+\b`)
	portRegex  = regexp.MustCompile(`\b\d{2,5}\b`)
	linkRegex  = regexp.MustCompile(`https?://[^\s"'<>]+`)
	authRegex  = regexp.MustCompile(`^(?:https?|socks4|socks5)://([^:@\s]+):([^@\s]+)@(.+)$`)

	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
	}
)

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.ProxyFile, "proxy", "", "Proxy file path")
	flag.StringVar(&cfg.TestURL, "url", "https://telegram.org", "Test URL")
	flag.IntVar(&cfg.Threads, "threads", 50, "Number of threads")
	flag.IntVar(&cfg.Timeout, "timeout", 7, "Timeout in seconds")
	flag.BoolVar(&cfg.OutputJSON, "json", false, "Save results as JSON")
	flag.BoolVar(&cfg.Score, "score", true, "Enable scoring")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable colors")
	flag.StringVar(&cfg.Types, "types", "", "Proxy types (http,socks5)")
	flag.StringVar(&cfg.SetProxy, "set-proxy", "", "Set system proxy")
	flag.BoolVar(&cfg.ApplyBest, "apply-best", false, "Apply best proxy")
	flag.BoolVar(&cfg.AutoDetect, "auto-detect", true, "Auto detect type")
	flag.BoolVar(&cfg.Download, "download", false, "Download proxies")
	flag.BoolVar(&cfg.Scrape, "scrape", false, "Scrape proxies from URL")
	flag.BoolVar(&cfg.ScrapeDeep, "deep", false, "Deep scrape")
	flag.StringVar(&cfg.ProxyType, "type", "all", "Proxy type for download")
	flag.BoolVar(&cfg.Insecure, "insecure", true, "Skip TLS verification")
	flag.StringVar(&cfg.Sources, "sources", "", "Custom sources for scraping")
	flag.Parse()

	RunProxyChecker(cfg)
}

func RunProxyChecker(config Config) {
	if config.SetProxy != "" {
		if config.SetProxy == "status" {
			checkProxyStatus()
			return
		}
		setSystemProxy(config.SetProxy)
		return
	}

	if config.ApplyBest {
		best := findAndApplyBestProxy(config)
		if best != "" {
			fmt.Printf("\nBest proxy applied to system: %s\n", best)
		}
		return
	}

	if config.Download {
		downloadProxies(config)
		return
	}

	if config.Scrape || config.ScrapeDeep {
		scrapeProxies(config)
		return
	}

	if config.ProxyFile == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Proxy file path: ")
		path, _ := reader.ReadString('\n')
		config.ProxyFile = strings.TrimSpace(path)
	}

	if config.Threads < 1 {
		config.Threads = 50
	}
	if config.Timeout < 1 {
		config.Timeout = 7
	}
	if config.TestURL == "" {
		config.TestURL = "https://telegram.org"
	}

	proxyList, err := readProxyFile(config.ProxyFile)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	if len(proxyList) == 0 {
		fmt.Println("No valid proxies found")
		return
	}

	totalProxies = len(proxyList)
	uiState.total = len(proxyList)
	uiState.results = nil
	uiState.completed = 0
	uiState.shouldQuit = false

	fmt.Printf("Testing %d proxies with %d threads...\n\n", len(proxyList), config.Threads)

	go uiLoop(config)

	jobs := make(chan string, len(proxyList))
	results := make(chan ProxyResult, len(proxyList))

	var wg sync.WaitGroup
	var collector sync.WaitGroup

	collector.Add(1)
	go func() {
		defer collector.Done()
		for r := range results {
			if r.Working {
				uiState.mu.Lock()
				uiState.results = append(uiState.results, r)
				uiState.mu.Unlock()
				saveValidProxy(r.Proxy)
			}
			atomic.AddInt32(&uiState.completed, 1)
		}
	}()

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxyStr := range jobs {
				results <- testProxy(proxyStr, config)
			}
		}()
	}

	for _, p := range proxyList {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)
	collector.Wait()

	uiState.mu.Lock()
	uiState.shouldQuit = true
	uiState.mu.Unlock()

	time.Sleep(200 * time.Millisecond)

	uiState.mu.RLock()
	finalResults := make([]ProxyResult, len(uiState.results))
	copy(finalResults, uiState.results)
	uiState.mu.RUnlock()

	if config.OutputJSON {
		saveJSON(finalResults)
	}

	printSummary(finalResults, config)
	printRecommendation(finalResults, config)
}

func readProxyFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var proxies []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}
	return uniqueStrings(proxies), scanner.Err()
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func uiLoop(config Config) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		uiState.mu.RLock()
		if uiState.shouldQuit {
			uiState.mu.RUnlock()
			return
		}
		results := make([]ProxyResult, len(uiState.results))
		copy(results, uiState.results)
		total := uiState.total
		completed := atomic.LoadInt32(&uiState.completed)
		uiState.mu.RUnlock()

		fmt.Print("\033[H\033[2J")
		fmt.Printf("Proxy Checker - Testing %d proxies\n", total)

		if total > 0 {
			progress := float64(completed) / float64(total) * 100
			fmt.Printf("Progress: %.1f%% (%d/%d) Working: %d\n\n", progress, completed, total, len(results))
		}

		if len(results) > 0 {
			sortResults(results, config)
			printTable(results, config)
		} else {
			fmt.Println("Waiting for results...")
		}
	}
}

func sortResults(results []ProxyResult, config Config) {
	sort.Slice(results, func(i, j int) bool {
		if config.Score && results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].LatencyMs != results[j].LatencyMs {
			return results[i].LatencyMs < results[j].LatencyMs
		}
		return results[i].Proxy < results[j].Proxy
	})
}

func printTable(results []ProxyResult, config Config) {
	green := "\033[32m"
	yellow := "\033[33m"
	red := "\033[31m"
	blue := "\033[34m"
	reset := "\033[0m"

	if config.NoColor {
		green, yellow, red, blue, reset = "", "", "", "", ""
	}

	fmt.Printf("%-4s %-22s %-10s %-10s %-12s %-10s %-8s %-6s %-6s %-6s\n",
		"#", "Proxy", "Type", "Latency", "Country", "Anonymity", "Speed", "Score", "IPv6", "Auth")
	fmt.Println(strings.Repeat("-", 110))

	for i, r := range results {
		if i >= 20 {
			break
		}

		latency := fmt.Sprintf("%dms", r.LatencyMs)
		if r.LatencyMs < 0 {
			latency = "FAIL"
		}

		country := r.Country
		if country == "" {
			country = "Unknown"
		}

		anonymity := r.Anonymity
		if anonymity == "" {
			anonymity = "-"
		}

		speed := r.Speed
		if speed == "" {
			speed = "-"
		}

		ipv6 := "❌"
		if r.IPv6 {
			ipv6 = "✅"
		}

		auth := "❌"
		if r.HasAuth {
			auth = "✅"
		}

		typeColor := blue
		if r.Type == "socks5" {
			typeColor = green
		} else if r.Type == "socks4" {
			typeColor = yellow
		} else if r.Type == "https" {
			typeColor = red
		}

		speedColor := green
		if speed == "medium" {
			speedColor = yellow
		} else if speed == "slow" {
			speedColor = red
		}

		fmt.Printf("%-4d %s%-22s%s %s%-10s%s %-10s %-12s %-10s %s%-8s%s %-6d %-6s %-6s\n",
			i+1, green, r.Proxy, reset, typeColor, r.Type, reset,
			latency, country, anonymity,
			speedColor, speed, reset,
			r.Score, ipv6, auth)
	}
}

func testProxy(proxyStr string, config Config) ProxyResult {
	result := ProxyResult{
		Proxy:     strings.TrimSpace(proxyStr),
		LatencyMs: -1,
		CheckTime: time.Now().Format(time.RFC3339),
	}

	hasAuth, user, pass := parseProxyAuth(proxyStr)
	result.HasAuth = hasAuth

	cleanProxy := removeProxyAuth(proxyStr)
	cleanProxy = strings.TrimPrefix(cleanProxy, "http://")
	cleanProxy = strings.TrimPrefix(cleanProxy, "https://")
	cleanProxy = strings.TrimPrefix(cleanProxy, "socks4://")
	cleanProxy = strings.TrimPrefix(cleanProxy, "socks5://")

	proxyType := config.Types
	if proxyType == "" {
		if config.AutoDetect {
			detected, err := detectProxyType(cleanProxy, config)
			if err == nil {
				proxyType = detected
			}
		}
		if proxyType == "" {
			proxyType = detectProxyTypeByPort(cleanProxy)
		}
	}
	if proxyType == "" {
		proxyType = "http"
	}
	result.Type = proxyType

	proxyWithAuth := cleanProxy
	if hasAuth {
		proxyWithAuth = fmt.Sprintf("%s://%s:%s@%s", proxyType, user, pass, cleanProxy)
	}

	start := time.Now()
	working, _, err := checkProxy(proxyWithAuth, proxyType, config.TestURL, config.Timeout, config.Insecure)
	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil || !working {
		if err != nil {
			result.Error = err.Error()
		}
		return result
	}

	result.Working = true
	result.IPv6 = checkIPv6(cleanProxy)
	result.Country, result.Provider = getGeoInfo(cleanProxy)
	result.Anonymity = checkAnonymity(proxyWithAuth, proxyType, config.TestURL, config.Timeout)
	result.Speed = getSpeedCategory(result.LatencyMs)
	result.Score = calculateScore(result, config)

	return result
}

func parseProxyAuth(proxyStr string) (bool, string, string) {
	m := authRegex.FindStringSubmatch(strings.TrimSpace(proxyStr))
	if len(m) == 4 {
		return true, m[1], m[2]
	}
	return false, "", ""
}

func removeProxyAuth(proxyStr string) string {
	m := authRegex.FindStringSubmatch(strings.TrimSpace(proxyStr))
	if len(m) == 4 {
		return m[3]
	}
	return proxyStr
}

func checkIPv6(proxyStr string) bool {
	host, _, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return strings.Count(proxyStr, ":") >= 2
	}
	return strings.Count(host, ":") >= 2
}

func detectProxyType(proxyStr string, config Config) (string, error) {
	types := []string{"socks5", "socks4", "https", "http"}
	for _, t := range types {
		working, _, _ := checkProxy(proxyStr, t, config.TestURL, 1, config.Insecure)
		if working {
			return t, nil
		}
	}
	return "", fmt.Errorf("unable to detect proxy type")
}

func detectProxyTypeByPort(proxyStr string) string {
	host, portStr, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return "http"
	}

	port, _ := strconv.Atoi(portStr)

	if strings.Contains(host, ":") {
		return "socks5"
	}

	switch port {
	case 1080, 1081, 1085, 9050, 9051, 9150:
		return "socks5"
	case 8080, 3128, 8888, 80, 8000:
		return "http"
	case 443, 8443, 9443:
		return "https"
	default:
		return "http"
	}
}

func checkProxy(proxyStr, proxyType, testURL string, timeoutSec int, insecure bool) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	client, err := createClient(proxyStr, proxyType, timeoutSec, insecure)
	if err != nil {
		return false, 0, err
	}

	testURLs := []string{
		testURL,
		"https://www.google.com/generate_204",
		"https://cloudflare.com/cdn-cgi/trace",
		"https://httpbin.org/get",
	}

	var lastErr error
	for _, u := range testURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", userAgents[0])
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Connection", "keep-alive")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode < 400 {
			return true, resp.StatusCode, nil
		}
		lastErr = fmt.Errorf("status code %d", resp.StatusCode)
	}

	return false, 0, lastErr
}

func createClient(proxyStr, proxyType string, timeout int, insecure bool) (*http.Client, error) {
	switch proxyType {
	case "http", "https":
		return createHTTPClient(proxyStr, timeout, insecure)
	case "socks5":
		return createSocks5Client(proxyStr, timeout)
	case "socks4":
		return createSocks4Client(proxyStr, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", proxyType)
	}
}

func createHTTPClient(proxyStr string, timeout int, insecure bool) (*http.Client, error) {
	if !strings.HasPrefix(proxyStr, "http://") && !strings.HasPrefix(proxyStr, "https://") {
		proxyStr = "http://" + proxyStr
	}

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

func createSocks5Client(proxyStr string, timeout int) (*http.Client, error) {
	var auth *proxy.Auth

	if strings.Contains(proxyStr, "@") {
		parts := strings.SplitN(proxyStr, "@", 2)
		if len(parts) == 2 {
			proxyStr = parts[1]
			userPass := strings.SplitN(parts[0], ":", 2)
			if len(userPass) == 2 {
				auth = &proxy.Auth{
					User:     userPass[0],
					Password: userPass[1],
				}
			}
		}
	}

	proxyStr = strings.TrimPrefix(proxyStr, "socks5://")

	host, portStr, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid socks5 proxy format: %v", err)
	}

	port, _ := strconv.Atoi(portStr)

	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, strconv.Itoa(port)), auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

func createSocks4Client(proxyStr string, timeout int) (*http.Client, error) {
	proxyStr = strings.TrimPrefix(proxyStr, "socks4://")

	host, portStr, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid socks4 proxy: %v", err)
	}
	proxyPort, _ := strconv.Atoi(portStr)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(proxyPort)))
			if err != nil {
				return nil, err
			}

			targetHost, targetPort, err := net.SplitHostPort(addr)
			if err != nil {
				conn.Close()
				return nil, err
			}

			targetIP, err := net.ResolveIPAddr("ip", targetHost)
			if err != nil {
				conn.Close()
				return nil, err
			}

			ipBytes := targetIP.IP.To4()
			if ipBytes == nil {
				conn.Close()
				return nil, fmt.Errorf("socks4 requires IPv4 target")
			}

			targetPortInt, _ := strconv.Atoi(targetPort)
			if targetPortInt < 0 || targetPortInt > 65535 {
				conn.Close()
				return nil, fmt.Errorf("invalid target port")
			}

			request := []byte{
				0x04, 0x01,
				byte(targetPortInt >> 8), byte(targetPortInt & 0xFF),
				ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
				0x00,
			}

			conn.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			if _, err := conn.Write(request); err != nil {
				conn.Close()
				return nil, err
			}

			buf := make([]byte, 8)
			conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			if _, err := io.ReadFull(conn, buf); err != nil {
				conn.Close()
				return nil, err
			}

			if len(buf) < 2 || buf[1] != 0x5A {
				conn.Close()
				return nil, fmt.Errorf("socks4 handshake failed")
			}

			return conn, nil
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}, nil
}

func checkAnonymity(proxyStr, proxyType, testURL string, timeout int) string {
	key := proxyType + "|" + proxyStr

	anonymityMu.Lock()
	if val, ok := anonymityCache[key]; ok {
		anonymityMu.Unlock()
		return val
	}
	anonymityMu.Unlock()

	client, err := createClient(proxyStr, proxyType, timeout, true)
	if err != nil {
		return "unknown"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	testURLs := []string{
		"https://httpbin.org/headers",
		"https://httpbin.org/get",
	}

	for _, u := range testURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgents[0])

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			continue
		}

		headers, ok := data["headers"].(map[string]interface{})
		if !ok {
			continue
		}

		if _, ok := headers["X-Forwarded-For"]; ok {
			anonymityMu.Lock()
			anonymityCache[key] = "transparent"
			anonymityMu.Unlock()
			return "transparent"
		}
		if _, ok := headers["X-Real-IP"]; ok {
			anonymityMu.Lock()
			anonymityCache[key] = "transparent"
			anonymityMu.Unlock()
			return "transparent"
		}
		if _, ok := headers["Via"]; ok {
			anonymityMu.Lock()
			anonymityCache[key] = "anonymous"
			anonymityMu.Unlock()
			return "anonymous"
		}
	}

	anonymityMu.Lock()
	anonymityCache[key] = "elite"
	anonymityMu.Unlock()
	return "elite"
}

func getGeoInfo(proxyStr string) (string, string) {
	host, _, err := net.SplitHostPort(proxyStr)
	if err != nil {
		host = strings.Trim(proxyStr, "[]")
	}

	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return "Local", "Local"
	}

	geoCacheMu.Lock()
	if info, ok := geoCache[host]; ok {
		geoCacheMu.Unlock()
		return info.Country, info.Provider
	}
	geoCacheMu.Unlock()

	client := &http.Client{Timeout: 5 * time.Second}

	var country, provider string

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=countryCode,isp", host)
	resp, err := client.Get(url)
	if err == nil {
		var data map[string]interface{}
		if json.NewDecoder(resp.Body).Decode(&data) == nil {
			if status, ok := data["status"].(string); ok && status == "success" {
				country, _ = data["countryCode"].(string)
				provider, _ = data["isp"].(string)
			}
		}
		resp.Body.Close()
	}

	if country == "" && provider == "" {
		url := fmt.Sprintf("https://ipinfo.io/%s/json", host)
		resp, err := client.Get(url)
		if err == nil {
			var data map[string]interface{}
			if json.NewDecoder(resp.Body).Decode(&data) == nil {
				country, _ = data["country"].(string)
				provider, _ = data["org"].(string)
			}
			resp.Body.Close()
		}
	}

	if country == "" && provider == "" {
		url := fmt.Sprintf("https://ipwhois.app/json/%s", host)
		resp, err := client.Get(url)
		if err == nil {
			var data map[string]interface{}
			if json.NewDecoder(resp.Body).Decode(&data) == nil {
				country, _ = data["country"].(string)
				provider, _ = data["isp"].(string)
			}
			resp.Body.Close()
		}
	}

	geoCacheMu.Lock()
	geoCache[host] = GeoInfo{Country: country, Provider: provider}
	geoCacheMu.Unlock()

	return country, provider
}

func getSpeedCategory(latency int64) string {
	if latency < 100 {
		return "fast"
	} else if latency < 500 {
		return "medium"
	}
	return "slow"
}

func calculateScore(result ProxyResult, config Config) int {
	score := 0

	if result.LatencyMs < 100 {
		score += 30
	} else if result.LatencyMs < 300 {
		score += 22
	} else if result.LatencyMs < 500 {
		score += 14
	} else if result.LatencyMs < 1000 {
		score += 6
	}

	switch result.Type {
	case "socks5":
		score += 15
	case "socks4":
		score += 10
	case "https":
		score += 12
	case "http":
		score += 5
	}

	switch result.Anonymity {
	case "elite":
		score += 25
	case "anonymous":
		score += 15
	case "transparent":
		score += 5
	}

	if result.IPv6 {
		score += 5
	}
	if result.HasAuth {
		score += 3
	}
	if result.Country != "" && result.Country != "Unknown" {
		score += 2
	}
	if result.Provider != "" && result.Provider != "Unknown" {
		score += 2
	}

	if score > 100 {
		score = 100
	}
	return score
}

func saveValidProxy(proxy string) {
	validProxyMu.Lock()
	defer validProxyMu.Unlock()

	f, err := os.OpenFile("valid_proxies.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(proxy + "\n")
}

func saveJSON(results []ProxyResult) {
	f, err := os.Create("proxy_results.json")
	if err != nil {
		fmt.Println("Error creating JSON:", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(results)
	fmt.Println("\nResults saved to proxy_results.json")
}

func printSummary(results []ProxyResult, config Config) {
	if len(results) == 0 {
		fmt.Println("\nNo working proxies found")
		return
	}

	var totalScore, totalLatency int64
	for _, r := range results {
		totalScore += int64(r.Score)
		totalLatency += r.LatencyMs
	}

	avgScore := totalScore / int64(len(results))
	avgLatency := totalLatency / int64(len(results))

	fmt.Println("\n========================================")
	fmt.Printf("Total Proxies in File: %d\n", totalProxies)
	fmt.Printf("Working Proxies: %d\n", len(results))
	if totalProxies > 0 {
		fmt.Printf("Success Rate: %.1f%%\n", float64(len(results))/float64(totalProxies)*100)
	}
	fmt.Printf("Average Latency: %dms\n", avgLatency)
	fmt.Printf("Average Score: %d/100\n", avgScore)
	fmt.Printf("Best Proxy: %s (%dms)\n", results[0].Proxy, results[0].LatencyMs)
	fmt.Println("========================================")
}

func printRecommendation(results []ProxyResult, config Config) {
	if len(results) == 0 {
		fmt.Println("\nNo working proxies found to recommend")
		return
	}

	sorted := make([]ProxyResult, len(results))
	copy(sorted, results)
	sortResults(sorted, config)
	best := sorted[0]

	fmt.Println("\n========================================")
	fmt.Println("RECOMMENDED PROXY CONFIGURATION")
	fmt.Printf("Proxy: %s\n", best.Proxy)
	fmt.Printf("Type: %s\n", best.Type)
	fmt.Printf("Latency: %dms\n", best.LatencyMs)
	fmt.Printf("Anonymity: %s\n", best.Anonymity)
	fmt.Printf("Speed: %s\n", best.Speed)
	fmt.Printf("IPv6: %v\n", best.IPv6)
	fmt.Printf("Auth: %v\n", best.HasAuth)
	fmt.Printf("Score: %d/100\n", best.Score)
	fmt.Println("========================================")
}

func downloadProxies(config Config) {
	sources := map[string][]string{
		"socks5": {
			"https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks5.txt",
			"https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/socks5-proxy-list-by-EbraSha.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
		},
		"socks4": {
			"https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks4.txt",
			"https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/socks4-proxy-list-by-EbraSha.txt",
		},
		"https": {
			"https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/https.txt",
			"https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/https-proxy-list-by-EbraSha.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
		},
		"http": {
			"https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/http.txt",
			"https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/http-proxy-list-by-EbraSha.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt",
		},
	}

	proxyType := config.ProxyType
	if proxyType == "" {
		proxyType = "all"
	}

	fmt.Printf("Downloading proxies (type: %s)...\n", proxyType)

	var allProxies []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for t, urls := range sources {
		if proxyType != "all" && proxyType != t {
			continue
		}

		for _, url := range urls {
			wg.Add(1)
			go func(url, typ string) {
				defer wg.Done()
				proxies := fetchProxies(url)
				if len(proxies) > 0 {
					mu.Lock()
					for _, p := range proxies {
						if !strings.Contains(p, "://") {
							p = typ + "://" + p
						}
						allProxies = append(allProxies, p)
					}
					mu.Unlock()
					fmt.Printf("  Downloaded %d proxies from %s\n", len(proxies), url)
				}
			}(url, t)
		}
	}

	wg.Wait()

	if len(allProxies) == 0 {
		fmt.Println("No proxies downloaded")
		return
	}

	allProxies = uniqueStrings(allProxies)

	filename := "proxies.txt"
	if proxyType != "all" {
		filename = proxyType + "_proxies.txt"
	}

	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer f.Close()

	for _, p := range allProxies {
		f.WriteString(p + "\n")
	}

	fmt.Printf("\nDownloaded %d proxies to %s\n", len(allProxies), filename)
}

func fetchProxies(urlStr string) []string {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(body), "\n")
	var proxies []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}
	return proxies
}

func scrapeProxies(config Config) {
	if config.ScrapeDeep {
		fmt.Println("Deep scraping proxies...")
	} else {
		fmt.Println("Scraping proxies...")
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Please provide URLs to scrape")
		fmt.Println("Example: program -scrape https://example.com/proxies.txt")
		return
	}

	var allProxies []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, url := range args {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			proxies := scrapeURL(u, config.ScrapeDeep)
			mu.Lock()
			allProxies = append(allProxies, proxies...)
			mu.Unlock()
			fmt.Printf("  Scraped %d proxies from %s\n", len(proxies), u)
		}(url)
	}

	wg.Wait()

	if len(allProxies) == 0 {
		fmt.Println("No proxies found")
		return
	}

	allProxies = uniqueStrings(allProxies)

	filename := "scraped_proxies.txt"
	if config.ScrapeDeep {
		filename = "deep_scraped_proxies.txt"
	}

	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer f.Close()

	for _, p := range allProxies {
		f.WriteString(p + "\n")
	}

	fmt.Printf("\nScraped %d proxies to %s\n", len(allProxies), filename)
}

func scrapeURL(urlStr string, deep bool) []string {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	content := string(body)
	var proxies []string

	matches := proxyRegex.FindAllString(content, -1)
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if m != "" && !strings.HasPrefix(m, "#") {
			proxies = append(proxies, m)
		}
	}

	ips := ipRegex.FindAllString(content, -1)
	ports := portRegex.FindAllString(content, -1)

	if len(ips) > 0 && len(ports) > 0 {
		minLen := len(ips)
		if len(ports) < minLen {
			minLen = len(ports)
		}
		for i := 0; i < minLen; i++ {
			port := ports[i]
			if len(port) >= 2 && len(port) <= 5 {
				proxy := ips[i] + ":" + port
				if !contains(proxies, proxy) {
					proxies = append(proxies, proxy)
				}
			}
		}
	}

	ipv6s := ipv6Regex.FindAllString(content, -1)
	if len(ipv6s) > 0 && len(ports) > 0 {
		minLen := len(ipv6s)
		if len(ports) < minLen {
			minLen = len(ports)
		}
		for i := 0; i < minLen; i++ {
			port := ports[i]
			if len(port) >= 2 && len(port) <= 5 {
				proxy := "[" + ipv6s[i] + "]:" + port
				if !contains(proxies, proxy) {
					proxies = append(proxies, proxy)
				}
			}
		}
	}

	if deep {
		links := linkRegex.FindAllString(content, -1)
		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, link := range links {
			if strings.Contains(link, ".txt") || strings.Contains(link, "raw.githubusercontent.com") {
				if !strings.Contains(link, urlStr) {
					wg.Add(1)
					go func(l string) {
						defer wg.Done()
						more := scrapeURL(l, false)
						mu.Lock()
						proxies = append(proxies, more...)
						mu.Unlock()
					}(link)
				}
			}
		}
		wg.Wait()
	}

	return uniqueStrings(proxies)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func findAndApplyBestProxy(config Config) string {
	candidates := []string{
		"http://127.0.0.1:8080",
		"socks5://127.0.0.1:1080",
		"http://127.0.0.1:3128",
	}

	fmt.Println("Finding best proxy...")

	var results []ProxyResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string, len(candidates))

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				result := testProxy(p, config)
				if result.Working {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}
		}()
	}

	for _, p := range candidates {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	if len(results) == 0 {
		fmt.Println("No working proxy found")
		return ""
	}

	sortResults(results, config)
	best := results[0]

	fmt.Printf("\nBest Proxy: %s\n", best.Proxy)
	fmt.Printf("  Type: %s\n", best.Type)
	fmt.Printf("  Latency: %dms\n", best.LatencyMs)
	fmt.Printf("  Anonymity: %s\n", best.Anonymity)
	fmt.Printf("  Speed: %s\n", best.Speed)
	fmt.Printf("  Score: %d/100\n", best.Score)

	setSystemProxy(best.Proxy)
	return best.Proxy
}

func setSystemProxy(proxyStr string) {
	fmt.Printf("\nSetting system proxy to: %s\n", proxyStr)
	fmt.Println(strings.Repeat("-", 40))

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "winhttp", "set", "proxy", proxyStr)
		if err := cmd.Run(); err != nil {
			fmt.Println("Error setting proxy on Windows:", err)
			fmt.Println("Try running as Administrator")
			return
		}
		fmt.Printf("Proxy set to %s on Windows\n", proxyStr)
	} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		os.Setenv("HTTP_PROXY", proxyStr)
		os.Setenv("HTTPS_PROXY", proxyStr)
		os.Setenv("ALL_PROXY", proxyStr)
		fmt.Printf("Proxy set to %s via environment variables\n", proxyStr)
	} else {
		fmt.Println("Proxy set successfully (simulated)")
	}
}

func checkProxyStatus() {
	fmt.Println("\nCurrent Proxy Settings:")
	fmt.Println(strings.Repeat("-", 40))

	fmt.Printf("HTTP_PROXY: %s\n", os.Getenv("HTTP_PROXY"))
	fmt.Printf("HTTPS_PROXY: %s\n", os.Getenv("HTTPS_PROXY"))
	fmt.Printf("ALL_PROXY: %s\n", os.Getenv("ALL_PROXY"))

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "winhttp", "show", "proxy")
		output, _ := cmd.Output()
		fmt.Printf("\nWindows WinHTTP Proxy:\n%s\n", string(output))
	}
}
