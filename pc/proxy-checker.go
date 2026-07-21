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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

type ProxyResult struct {
	Proxy      string `json:"proxy"`
	Type       string `json:"type"`
	Working    bool   `json:"working"`
	LatencyMs  int64  `json:"latency_ms"`
	Country    string `json:"country"`
	Provider   string `json:"provider"`
	Anonymity  string `json:"anonymity"`
	Speed      string `json:"speed"`
	Score      int    `json:"score"`
	CheckTime  string `json:"check_time"`
	Error      string `json:"error,omitempty"`
	IPv6       bool   `json:"ipv6"`
	HasAuth    bool   `json:"has_auth"`
}

type Config struct {
	ProxyFile     string
	Threads       int
	TestURL       string
	Timeout       int
	OutputJSON    bool
	Score         bool
	NoColor       bool
	Types         string
	SetProxy      string
	ApplyBest     bool
	AutoDetect    bool
	Download      bool
	Scrape        bool
	ScrapeDeep    bool
	Headers       string
	ProxyType     string
	Insecure      bool
}

var (
	cleanRegex      = regexp.MustCompile(`[^0-9a-zA-Z\.\:\-\[\]]`)
	proxyRegex      = regexp.MustCompile(`(?:socks5|socks4|https?):\/\/[^\s]+|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b`)
	ipRegex         = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	ipv6Regex       = regexp.MustCompile(`\b[0-9a-fA-F:]+:[0-9a-fA-F:]+\b`)
	portRegex       = regexp.MustCompile(`\b\d{2,5}\b`)
	mu              sync.Mutex
	allResults      []ProxyResult
	downloadedIP    = make(map[string]bool)
	ipMutex         sync.Mutex
	geoCache        = make(map[string]GeoInfo)
	geoCacheMu      sync.Mutex
	anonymityCache  = make(map[string]string)
	anonymityMu     sync.Mutex
	totalProxies    int
	proxyTypeRegex  = regexp.MustCompile(`^(socks5|socks4|https?):\/\/`)
	authRegex       = regexp.MustCompile(`^(socks5|socks4|https?):\/\/([^:]+):([^@]+)@`)
	ipv6Bracket     = regexp.MustCompile(`^\[[0-9a-fA-F:]+\]`)
)

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

var uiState = &UIState{}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
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
			fmt.Printf("\n✓ Best proxy (%s) applied to system\n", best)
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
		proxyPath, _ := reader.ReadString('\n')
		config.ProxyFile = strings.TrimSpace(proxyPath)
	}

	if config.Threads < 2 {
		config.Threads = 50
	}

	if config.TestURL == "" {
		config.TestURL = "https://telegram.org"
	}

	if config.Timeout == 0 {
		config.Timeout = 5
	}

	f, err := os.Open(config.ProxyFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var proxyList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxyList = append(proxyList, line)
		}
	}

	if len(proxyList) == 0 {
		fmt.Println("No valid proxies found")
		return
	}

	totalProxies = len(proxyList)
	uiState.total = len(proxyList)

	fmt.Printf("Testing %d proxies with %d threads...\n\n", len(proxyList), config.Threads)

	go uiLoop(config)

	jobs := make(chan string, len(proxyList))
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxyStr := range jobs {
				result := testProxy(proxyStr, config)
				if result.Working {
					uiState.mu.Lock()
					uiState.results = append(uiState.results, result)
					uiState.mu.Unlock()
					saveValidProxy(proxyStr)
				}
				atomic.AddInt32(&uiState.completed, 1)
			}
		}()
	}

	for _, proxy := range proxyList {
		jobs <- proxy
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

func GetResults() []ProxyResult {
	uiState.mu.RLock()
	defer uiState.mu.RUnlock()
	return uiState.results
}

func GetValidProxies() []string {
	uiState.mu.RLock()
	defer uiState.mu.RUnlock()
	var valid []string
	for _, r := range uiState.results {
		if r.Working {
			valid = append(valid, r.Proxy)
		}
	}
	return valid
}

func uiLoop(config Config) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		<-ticker.C
		uiState.mu.RLock()
		if uiState.shouldQuit {
			uiState.mu.RUnlock()
			return
		}
		results := make([]ProxyResult, len(uiState.results))
		copy(results, uiState.results)
		completed := atomic.LoadInt32(&uiState.completed)
		uiState.mu.RUnlock()

		fmt.Print("\033[H\033[2J")
		fmt.Printf("Proxy Checker - Testing %d proxies\n\n", uiState.total)

		progress := float64(completed) / float64(uiState.total) * 100
		fmt.Printf("Progress: %.1f%% (%d/%d) | Working: %d\n\n",
			progress, completed, uiState.total, len(results))

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
		if config.Score {
			if results[i].Score != results[j].Score {
				return results[i].Score > results[j].Score
			}
			return results[i].LatencyMs < results[j].LatencyMs
		}
		return results[i].LatencyMs < results[j].LatencyMs
	})
}

func printTable(results []ProxyResult, config Config) {
	green := "\033[32m"
	yellow := "\033[33m"
	red := "\033[31m"
	blue := "\033[34m"
	reset := "\033[0m"

	if config.NoColor {
		green = ""
		yellow = ""
		red = ""
		blue = ""
		reset = ""
	}

	fmt.Printf("%-4s %-20s %-10s %-10s %-12s %-10s %-8s %-6s %-6s %-6s\n",
		"#", "Proxy", "Type", "Latency", "Country", "Anonymity", "Speed", "Score", "IPv6", "Auth")
	fmt.Println(strings.Repeat("-", 110))

	for i, result := range results {
		if i >= 20 {
			break
		}

		latencyStr := fmt.Sprintf("%dms", result.LatencyMs)
		if result.LatencyMs < 0 {
			latencyStr = "FAIL"
		}

		country := result.Country
		if country == "" {
			country = "Unknown"
		}

		anonymity := result.Anonymity
		if anonymity == "" {
			anonymity = "-"
		}

		speed := result.Speed
		if speed == "" {
			speed = "-"
		}

		ipv6Str := "❌"
		if result.IPv6 {
			ipv6Str = "✅"
		}

		authStr := "❌"
		if result.HasAuth {
			authStr = "✅"
		}

		typeColor := blue
		if result.Type == "socks5" {
			typeColor = green
		} else if result.Type == "socks4" {
			typeColor = yellow
		}

		speedColor := green
		if speed == "medium" {
			speedColor = yellow
		} else if speed == "slow" {
			speedColor = red
		}

		rank := fmt.Sprintf("#%d", i+1)
		fmt.Printf("%s%-4s %-20s %s%-10s%s %-10s %-12s %-10s %s%-8s%s %-6d %-6s %-6s%s\n",
			green, rank, result.Proxy,
			typeColor, result.Type, reset,
			latencyStr,
			country,
			anonymity,
			speedColor, speed, reset,
			result.Score, ipv6Str, authStr, reset)
	}
}

func testProxy(proxyStr string, config Config) ProxyResult {
	result := ProxyResult{
		Proxy:     proxyStr,
		LatencyMs: -1,
	}

	hasAuth, authUser, authPass := parseProxyAuth(proxyStr)
	result.HasAuth = hasAuth

	cleanProxy := removeProxyAuth(proxyStr)

	var proxyType string

	if config.Types != "" {
		types := strings.Split(config.Types, ",")
		proxyType = strings.TrimSpace(types[0])
	} else if config.AutoDetect {
		detected, err := detectProxyTypeFast(cleanProxy, config)
		if err == nil {
			proxyType = detected
		} else {
			result.Error = err.Error()
			return result
		}
	} else {
		proxyType = detectProxyTypeByPort(cleanProxy)
	}

	if proxyType == "" {
		result.Error = "Unable to detect proxy type"
		return result
	}

	result.Type = proxyType

	proxyWithAuth := cleanProxy
	if hasAuth {
		if proxyType == "socks5" || proxyType == "http" || proxyType == "https" {
			proxyWithAuth = fmt.Sprintf("%s://%s:%s@%s", proxyType, authUser, authPass, cleanProxy)
		}
	}

	start := time.Now()
	working, _, err := checkProxyReal(proxyWithAuth, proxyType, config.TestURL, config.Timeout)
	latency := time.Since(start).Milliseconds()

	if err != nil || !working {
		if err != nil {
			result.Error = err.Error()
		}
		return result
	}

	result.Working = true
	result.LatencyMs = latency

	result.IPv6 = checkIPv6(cleanProxy)

	result.Country, result.Provider = getProxyGeoIP(cleanProxy)
	result.Anonymity = checkAnonymityReal(proxyWithAuth, proxyType, config.TestURL, config.Timeout)
	result.Speed = getSpeedCategory(latency)
	result.Score = calculateProxyScore(result, config)

	return result
}

func parseProxyAuth(proxyStr string) (bool, string, string) {
	matches := authRegex.FindStringSubmatch(proxyStr)
	if len(matches) == 4 {
		return true, matches[2], matches[3]
	}
	return false, "", ""
}

func removeProxyAuth(proxyStr string) string {
	return authRegex.ReplaceAllString(proxyStr, "")
}

func checkIPv6(proxyStr string) bool {
	proxyStr = proxyTypeRegex.ReplaceAllString(proxyStr, "")
	if strings.Contains(proxyStr, "[") && strings.Contains(proxyStr, "]") {
		return true
	}
	host, _, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return strings.Contains(proxyStr, ":")
	}
	return strings.Contains(host, ":")
}

func detectProxyTypeFast(proxyStr string, config Config) (string, error) {
	types := []string{"http", "socks5", "socks4"}

	for _, t := range types {
		working, _, _ := checkProxyReal(proxyStr, t, config.TestURL, 1)
		if working {
			return t, nil
		}
	}

	return "", fmt.Errorf("unable to detect proxy type")
}

func detectProxyTypeByPort(proxyStr string) string {
	if match := proxyTypeRegex.FindString(proxyStr); match != "" {
		return strings.TrimSuffix(match, "://")
	}

	host, portStr, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return "http"
	}

	port, _ := strconv.Atoi(portStr)

	if strings.Contains(host, ":") {
		return "socks5"
	}

	switch port {
	case 1080:
		return "socks5"
	case 1081:
		return "socks4"
	case 8080, 3128, 8888, 80:
		return "http"
	case 443, 8443:
		return "https"
	}

	return "http"
}

func checkProxyReal(proxyStr, proxyType, testURL string, timeoutSec int) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var client *http.Client
	var err error

	switch proxyType {
	case "http":
		client, err = createHTTPClient(proxyStr, timeoutSec)
	case "https":
		client, err = createHTTPSClient(proxyStr, timeoutSec)
	case "socks4":
		client, err = createSocks4Client(proxyStr, testURL, timeoutSec)
	case "socks5":
		client, err = createSocks5Client(proxyStr, timeoutSec)
	default:
		return false, 0, fmt.Errorf("unsupported proxy type: %s", proxyType)
	}

	if err != nil {
		return false, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("User-Agent", userAgents[0])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	if statusCode >= 200 && statusCode < 400 {
		return true, statusCode, nil
	}

	if statusCode == 403 || statusCode == 404 || statusCode == 429 {
		return true, statusCode, nil
	}

	if statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308 {
		return true, statusCode, nil
	}

	return false, statusCode, fmt.Errorf("status code: %d", statusCode)
}

func createHTTPClient(proxyStr string, timeout int) (*http.Client, error) {
	if !strings.HasPrefix(proxyStr, "http://") && !strings.HasPrefix(proxyStr, "https://") {
		proxyStr = "http://" + proxyStr
	}

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: 0,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
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

func createHTTPSClient(proxyStr string, timeout int) (*http.Client, error) {
	if !strings.HasPrefix(proxyStr, "https://") {
		proxyStr = "https://" + proxyStr
	}

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: 0,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
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

func createSocks4Client(proxyStr, testURL string, timeout int) (*http.Client, error) {
	proxyStr = strings.TrimPrefix(proxyStr, "socks4://")

	host, portStr, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid socks4 proxy format: %v", err)
	}
	proxyPort, _ := strconv.Atoi(portStr)

	parsedURL, err := url.Parse(testURL)
	if err != nil {
		return nil, err
	}
	targetHost := parsedURL.Hostname()
	targetPort := parsedURL.Port()
	if targetPort == "" {
		if parsedURL.Scheme == "https" {
			targetPort = "443"
		} else {
			targetPort = "80"
		}
	}

	targetIP, err := net.ResolveIPAddr("ip", targetHost)
	if err != nil {
		targetIP = &net.IPAddr{IP: net.ParseIP("1.2.3.4")}
	}

	targetPortInt, _ := strconv.Atoi(targetPort)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
			conn, err := dialer.DialContext(ctx, network, fmt.Sprintf("%s:%d", host, proxyPort))
			if err != nil {
				return nil, err
			}

			ipBytes := targetIP.IP.To4()
			if ipBytes == nil {
				conn.Close()
				return nil, fmt.Errorf("invalid target IP")
			}

			request := []byte{
				0x04, 0x01,
				byte(targetPortInt >> 8), byte(targetPortInt & 0xFF),
				ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
				0x00,
			}

			conn.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			_, err = conn.Write(request)
			if err != nil {
				conn.Close()
				return nil, err
			}

			buf := make([]byte, 8)
			conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			_, err = conn.Read(buf)
			if err != nil {
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
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
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
	proxyStr = strings.TrimPrefix(proxyStr, "socks5://")

	host, portStr, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid socks5 proxy format: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	var auth *proxy.Auth
	if strings.Contains(proxyStr, "@") {
		parts := strings.Split(proxyStr, "@")
		if len(parts) == 2 {
			userPass := strings.Split(parts[0], ":")
			if len(userPass) == 2 {
				auth = &proxy.Auth{
					User:     userPass[0],
					Password: userPass[1],
				}
			}
		}
	}

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", host, port), auth, proxy.Direct)
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
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
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

func checkAnonymityReal(proxyStr, proxyType, testURL string, timeout int) string {
	anonymityMu.Lock()
	if val, ok := anonymityCache[proxyStr]; ok {
		anonymityMu.Unlock()
		return val
	}
	anonymityMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var client *http.Client
	var err error

	switch proxyType {
	case "http":
		client, err = createHTTPClient(proxyStr, timeout)
	case "https":
		client, err = createHTTPSClient(proxyStr, timeout)
	case "socks4":
		client, err = createSocks4Client(proxyStr, "https://httpbin.org", timeout)
	case "socks5":
		client, err = createSocks5Client(proxyStr, timeout)
	default:
		return "unknown"
	}

	if err != nil {
		return "unknown"
	}

	testURLs := []string{
		"https://httpbin.org/headers",
		"https://api.ipify.org?format=json",
		"https://httpbin.org/get",
	}

	var anonymity string
	for _, url := range testURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
			anonymity = "transparent"
		} else if _, ok := headers["X-Real-IP"]; ok {
			anonymity = "transparent"
		} else if _, ok := headers["Forwarded"]; ok {
			anonymity = "transparent"
		} else if _, ok := headers["Via"]; ok {
			anonymity = "anonymous"
		} else if _, ok := headers["Client-IP"]; ok {
			anonymity = "transparent"
		} else {
			anonymity = "elite"
		}

		if anonymity != "" {
			break
		}
	}

	if anonymity == "" {
		anonymity = "unknown"
	}

	anonymityMu.Lock()
	anonymityCache[proxyStr] = anonymity
	anonymityMu.Unlock()

	return anonymity
}

func getProxyGeoIP(proxyStr string) (string, string) {
	proxyStr = proxyTypeRegex.ReplaceAllString(proxyStr, "")

	host, _, err := net.SplitHostPort(proxyStr)
	if err != nil {
		return "", ""
	}
	ip := host

	if ip == "localhost" || ip == "127.0.0.1" {
		return "Local", "Local"
	}

	geoCacheMu.Lock()
	if info, ok := geoCache[ip]; ok {
		geoCacheMu.Unlock()
		return info.Country, info.Provider
	}
	geoCacheMu.Unlock()

	client := &http.Client{Timeout: 2 * time.Second}
	apis := []string{
		"http://ip-api.com/json/%s?fields=countryCode,isp",
		"https://ipwhois.app/json/%s",
		"https://ipinfo.io/%s/json",
	}

	var country, provider string
	for _, api := range apis {
		url := fmt.Sprintf(api, ip)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

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

	geoCacheMu.Lock()
	geoCache[ip] = GeoInfo{Country: country, Provider: provider}
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

func calculateProxyScore(result ProxyResult, config Config) int {
	score := 0

	if result.LatencyMs < 100 {
		score += 25
	} else if result.LatencyMs < 300 {
		score += 18
	} else if result.LatencyMs < 500 {
		score += 10
	} else if result.LatencyMs < 1000 {
		score += 5
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

	if result.Provider != "" && result.Provider != "Local" {
		score += 2
	}

	if score > 100 {
		score = 100
	}

	return score
}

func downloadProxies(config Config) {
	urls := map[string]string{
		"socks5": "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks5.txt",
		"socks4": "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks4.txt",
		"https":  "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/https.txt",
		"http":   "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/http.txt",
	}

	extraUrls := map[string]string{
		"socks5_ebrasha": "https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/socks5-proxy-list-by-EbraSha.txt",
		"socks4_ebrasha": "https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/socks4-proxy-list-by-EbraSha.txt",
		"https_ebrasha":  "https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/https-proxy-list-by-EbraSha.txt",
		"http_ebrasha":   "https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/main/http-proxy-list-by-EbraSha.txt",
	}

	var proxyType string
	if config.ProxyType != "" {
		proxyType = config.ProxyType
	} else {
		proxyType = "all"
	}

	fmt.Printf("Downloading proxies...\n")

	var allProxies []string

	if proxyType == "all" || proxyType == "socks5" {
		allProxies = append(allProxies, fetchURL(urls["socks5"])...)
		allProxies = append(allProxies, fetchURL(extraUrls["socks5_ebrasha"])...)
	}
	if proxyType == "all" || proxyType == "socks4" {
		allProxies = append(allProxies, fetchURL(urls["socks4"])...)
		allProxies = append(allProxies, fetchURL(extraUrls["socks4_ebrasha"])...)
	}
	if proxyType == "all" || proxyType == "https" {
		allProxies = append(allProxies, fetchURL(urls["https"])...)
		allProxies = append(allProxies, fetchURL(extraUrls["https_ebrasha"])...)
	}
	if proxyType == "all" || proxyType == "http" {
		allProxies = append(allProxies, fetchURL(urls["http"])...)
		allProxies = append(allProxies, fetchURL(extraUrls["http_ebrasha"])...)
	}

	if len(allProxies) == 0 {
		fmt.Println("No proxies downloaded")
		return
	}

	unique := make(map[string]bool)
	var result []string
	for _, p := range allProxies {
		if !unique[p] {
			unique[p] = true
			result = append(result, p)
		}
	}

	filename := fmt.Sprintf("%s_proxies.txt", proxyType)
	if proxyType == "all" {
		filename = "all_proxies.txt"
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	for _, p := range result {
		file.WriteString(p + "\n")
	}

	fmt.Printf("✓ Downloaded %d proxies to %s\n", len(result), filename)
}

func fetchURL(urlStr string) []string {
	client := getHTTPClient()
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
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxies = append(proxies, line)
	}

	return proxies
}

func scrapeProxies(config Config) {
	if config.ScrapeDeep {
		fmt.Println("Deep scraping proxies from URL...")
	} else {
		fmt.Println("Scraping proxies from URL...")
	}

	var allProxies []string
	var mu sync.Mutex

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Please provide a URL to scrape")
		fmt.Println("Example: ct.exe -proxy-scrape https://example.com/proxies.txt")
		return
	}

	urls := args

	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			proxies := scrapeURL(url, config.ScrapeDeep)
			mu.Lock()
			allProxies = append(allProxies, proxies...)
			mu.Unlock()
		}(url)
	}
	wg.Wait()

	if len(allProxies) == 0 {
		fmt.Println("No proxies found")
		return
	}

	unique := make(map[string]bool)
	var result []string
	for _, p := range allProxies {
		if !unique[p] {
			unique[p] = true
			result = append(result, p)
		}
	}

	filename := "scraped_proxies.txt"
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	for _, p := range result {
		file.WriteString(p + "\n")
	}

	fmt.Printf("✓ Scraped %d proxies to %s\n", len(result), filename)
}

func scrapeURL(urlStr string, deep bool) []string {
	client := getHTTPClient()
	var proxies []string

	resp, err := client.Get(urlStr)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", urlStr, err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", urlStr, err)
		return nil
	}

	content := string(body)

	if strings.Contains(urlStr, "freeproxy.world") {
		proxyType := "socks4"
		if strings.Contains(urlStr, "type=socks5") {
			proxyType = "socks5"
		} else if strings.Contains(urlStr, "type=https") {
			proxyType = "https"
		} else if strings.Contains(urlStr, "type=http") {
			proxyType = "http"
		}

		proxies = scrapeFreeproxyWorld(content, proxyType)

		if deep {
			maxPage := findMaxPage(content)
			baseURL := strings.Split(urlStr, "&page=")[0]
			if maxPage > 1 {
				fmt.Printf("Found %d pages, scraping all...\n", maxPage)
				var wg sync.WaitGroup
				var mu sync.Mutex

				for page := 2; page <= maxPage && page <= 50; page++ {
					wg.Add(1)
					go func(page int) {
						defer wg.Done()
						pageURL := fmt.Sprintf("%s&page=%d", baseURL, page)
						fmt.Printf("Scraping page %d...\n", page)
						moreProxies := scrapeURL(pageURL, false)
						mu.Lock()
						proxies = append(proxies, moreProxies...)
						mu.Unlock()
					}(page)
				}
				wg.Wait()
			}
		}
	} else {
		matches := proxyRegex.FindAllString(content, -1)
		for _, match := range matches {
			match = strings.TrimSpace(match)
			if match != "" && !strings.HasPrefix(match, "#") {
				proxies = append(proxies, match)
			}
		}

		ips := ipRegex.FindAllString(content, -1)
		ipv6s := ipv6Regex.FindAllString(content, -1)
		ports := portRegex.FindAllString(content, -1)

		if len(ips) > 0 && len(ports) > 0 {
			portIdx := 0
			for _, ip := range ips {
				if portIdx < len(ports) {
					port := ports[portIdx]
					if len(port) >= 2 && len(port) <= 5 {
						proxy := ip + ":" + port
						if !contains(proxies, proxy) {
							proxies = append(proxies, proxy)
						}
						portIdx++
					}
				}
			}
		}

		if len(ipv6s) > 0 && len(ports) > 0 {
			portIdx := 0
			for _, ipv6 := range ipv6s {
				if portIdx < len(ports) {
					port := ports[portIdx]
					if len(port) >= 2 && len(port) <= 5 {
						proxy := "[" + ipv6 + "]:" + port
						if !contains(proxies, proxy) {
							proxies = append(proxies, proxy)
						}
						portIdx++
					}
				}
			}
		}
	}

	if deep {
		linkRegex := regexp.MustCompile(`https?://[^\s"']+`)
		links := linkRegex.FindAllString(content, -1)

		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, link := range links {
			if strings.Contains(link, ".txt") || strings.Contains(link, "raw.githubusercontent.com") {
				if !strings.Contains(link, urlStr) {
					wg.Add(1)
					go func(link string) {
						defer wg.Done()
						moreProxies := scrapeURL(link, false)
						mu.Lock()
						proxies = append(proxies, moreProxies...)
						mu.Unlock()
					}(link)
				}
			}
		}
		wg.Wait()
	}

	return proxies
}

func scrapeFreeproxyWorld(content, proxyType string) []string {
	var proxies []string
	lines := strings.Split(content, "\n")

	ipPattern := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

	var ips []string
	var ports []string

	for _, line := range lines {
		if strings.Contains(line, "<td") && strings.Contains(line, "style") {
			continue
		}
		if strings.Contains(line, "<a href=") && strings.Contains(line, "port=") {
			portMatch := regexp.MustCompile(`port=(\d+)`).FindStringSubmatch(line)
			if len(portMatch) > 1 {
				ports = append(ports, portMatch[1])
			}
		}
	}

	for _, line := range lines {
		if ipPattern.MatchString(line) {
			ips = append(ips, ipPattern.FindString(line))
		}
	}

	if len(ips) > 0 && len(ports) > 0 {
		minLen := len(ips)
		if len(ports) < minLen {
			minLen = len(ports)
		}
		for i := 0; i < minLen; i++ {
			proxy := ips[i] + ":" + ports[i]
			if !contains(proxies, proxy) {
				if proxyType != "" && proxyType != "all" {
					proxies = append(proxies, proxyType+"://"+proxy)
				} else {
					proxies = append(proxies, proxy)
				}
			}
		}
	}

	return proxies
}

func findMaxPage(content string) int {
	pageRegex := regexp.MustCompile(`/page=(\d+)`)
	matches := pageRegex.FindAllStringSubmatch(content, -1)

	maxPage := 1
	for _, match := range matches {
		if len(match) > 1 {
			page, _ := strconv.Atoi(match[1])
			if page > maxPage {
				maxPage = page
			}
		}
	}

	if maxPage == 1 {
		badgeRegex := regexp.MustCompile(`Found\s+(\d+)\s+proxies`)
		badgeMatch := badgeRegex.FindStringSubmatch(content)
		if len(badgeMatch) > 1 {
			total, _ := strconv.Atoi(badgeMatch[1])
			if total > 0 {
				maxPage = (total / 50) + 1
				if maxPage > 50 {
					maxPage = 50
				}
			}
		}
	}

	return maxPage
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func findAndApplyBestProxy(config Config) string {
	proxyList := []string{
		"socks5://127.0.0.1:1080",
		"http://127.0.0.1:8080",
	}

	fmt.Printf("Finding best proxy...\n\n")

	var results []ProxyResult
	var wg sync.WaitGroup
	jobs := make(chan string, len(proxyList))
	resultsMu := sync.Mutex{}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxy := range jobs {
				result := testProxy(proxy, config)
				resultsMu.Lock()
				if result.Working {
					results = append(results, result)
				}
				resultsMu.Unlock()
			}
		}()
	}

	for _, proxy := range proxyList {
		jobs <- proxy
	}
	close(jobs)
	wg.Wait()

	if len(results) == 0 {
		fmt.Println("No working proxy found")
		return ""
	}

	sortResults(results, config)
	best := results[0]

	fmt.Printf("Best Proxy: %s\n", best.Proxy)
	fmt.Printf("  Type: %s\n", best.Type)
	fmt.Printf("  Latency: %dms\n", best.LatencyMs)
	fmt.Printf("  Anonymity: %s\n", best.Anonymity)
	fmt.Printf("  Speed: %s\n", best.Speed)
	fmt.Printf("  Score: %d/100\n\n", best.Score)

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
			fmt.Println("Try: Run as Administrator")
			return
		}
		fmt.Printf("✓ Proxy set to %s on Windows\n", proxyStr)
	} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		os.Setenv("HTTP_PROXY", proxyStr)
		os.Setenv("HTTPS_PROXY", proxyStr)
		os.Setenv("ALL_PROXY", proxyStr)
		fmt.Printf("✓ Proxy set to %s via environment variables\n", proxyStr)
	} else {
		fmt.Println("Proxy set successfully (simulated)")
	}
}

func checkProxyStatus() {
	fmt.Println("\nCurrent Proxy Settings:")
	fmt.Println(strings.Repeat("-", 40))

	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")
	allProxy := os.Getenv("ALL_PROXY")

	fmt.Printf("HTTP_PROXY: %s\n", httpProxy)
	fmt.Printf("HTTPS_PROXY: %s\n", httpsProxy)
	fmt.Printf("ALL_PROXY: %s\n", allProxy)

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "winhttp", "show", "proxy")
		output, _ := cmd.Output()
		fmt.Printf("\nWindows WinHTTP Proxy:\n%s\n", string(output))
	}
}

func saveValidProxy(proxy string) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile("valid_proxies.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString(proxy + "\n")
}

func saveJSON(results []ProxyResult) {
	file, err := os.Create("proxy_results.json")
	if err != nil {
		fmt.Println("Error creating JSON:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(results)
	fmt.Println("\nResults saved to proxy_results.json")
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

	fmt.Printf("\n%s========================================%s\n", "\033[32m", "\033[0m")
	fmt.Printf("%s      RECOMMENDED PROXY CONFIGURATION%s\n", "\033[33m", "\033[0m")
	fmt.Printf("%s========================================%s\n", "\033[32m", "\033[0m")

	fmt.Printf("\nPrimary:   %s\n", best.Proxy)

	fmt.Printf("\nReason:\n")
	fmt.Printf("  • Type: %s\n", best.Type)
	fmt.Printf("  • Latency: %dms\n", best.LatencyMs)
	fmt.Printf("  • Anonymity: %s\n", best.Anonymity)
	fmt.Printf("  • Speed: %s\n", best.Speed)
	fmt.Printf("  • IPv6: %v\n", best.IPv6)
	fmt.Printf("  • Auth: %v\n", best.HasAuth)
	fmt.Printf("  • Score: %d/100\n", best.Score)

	fmt.Printf("%s========================================%s\n", "\033[32m", "\033[0m")
}

func printSummary(results []ProxyResult, config Config) {
	if len(results) == 0 {
		fmt.Println("\nNo working proxies found")
		return
	}

	var totalWorking int64
	var totalScore int64
	var avgLatency int64

	for _, r := range results {
		if r.Working {
			totalWorking++
			totalScore += int64(r.Score)
			avgLatency += r.LatencyMs
		}
	}

	avgScore := int64(0)
	avgLatencyVal := int64(0)
	if totalWorking > 0 {
		avgScore = totalScore / totalWorking
		avgLatencyVal = avgLatency / totalWorking
	}

	fmt.Printf("\n%s========================================%s\n", "\033[32m", "\033[0m")
	fmt.Printf("Total Proxies in File: %d\n", totalProxies)
	fmt.Printf("Working Proxies: %d\n", totalWorking)
	fmt.Printf("Success Rate: %.1f%%\n", float64(totalWorking)/float64(totalProxies)*100)
	fmt.Printf("Average Latency: %dms\n", avgLatencyVal)
	fmt.Printf("Average Score: %d/100\n", avgScore)
	if len(results) > 0 {
		fmt.Printf("Best Proxy: %s (%dms)\n", results[0].Proxy, results[0].LatencyMs)
	}
	fmt.Printf("========================================\n")
}
