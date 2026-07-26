package xp

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/proxy"
)

type TestResult struct {
	Index      int
	Config     string
	Alive      bool
	Latency    time.Duration
	ErrorMsg   string
	Server     string
	Protocol   string
	Network    string
	Country    string
	City       string
	ISP        string
	StatusCode int
	PublicIP   string
}

type GeoInfo struct {
	Country     string `json:"country"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	CountryCode string `json:"countryCode"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

type SourceConfig struct {
	Sources []string `json:"sources"`
}

type CheckerConfig struct {
	ConfigFile string
	Download   bool
	Limit      int
	Threads    int
	Timeout    float64
	AddSource  string
	TestURL    string
	NoColor    bool
	OutputFile string
	RegionSort bool
	RegionDir  string
}

type VMessConfig struct {
	V           string `json:"v"`
	Ps          string `json:"ps"`
	Add         string `json:"add"`
	Port        string `json:"port"`
	ID          string `json:"id"`
	Aid         string `json:"aid"`
	Net         string `json:"net"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	TLS         string `json:"tls"`
	Sni         string `json:"sni"`
	Alpn        string `json:"alpn"`
	Fingerprint string `json:"fp"`
	Security    string `json:"security"`
}

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorPurple = "\033[35m"
	colorWhite  = "\033[37m"
)

var defaultSources = []string{
	"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
	"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt",
	"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/raw/refs/heads/main/trojan_configs.txt",
	"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/raw/refs/heads/main/ss_configs.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/raw/refs/heads/main/Sub1.txt",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/raw/refs/heads/main/V2RAY_RAW.txt",
	"https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/raw/refs/heads/main/sub.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub5.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub6.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub7.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub8.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ssr.txt",
}

var geoAPIs = []string{
	"http://ip-api.com/json/%s?fields=status,message,country,city,isp,org,countryCode",
	"https://ipinfo.io/%s/json",
}

var (
	configFileName = "sources.json"
	geoCache       = make(map[string]GeoInfo)
	cacheMutex     sync.Mutex
	appendMutex    sync.Mutex
	geoFallback    int
	publicIPChecks = []string{
		"https://api.ipify.org?format=text",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	aliveTargets = []string{
		"https://www.gstatic.com/generate_204",
		"https://cp.cloudflare.com/generate_204",
		"https://clients3.google.com/generate_204",
		"https://github.com/",
		"https://www.bing.com/",
		"https://www.apple.com/",
	}
)

func RunChecker(config CheckerConfig) {
	if config.AddSource != "" {
		if err := addSourceToFile(config.AddSource); err != nil {
			fmt.Printf("%sError adding source: %v%s\n", colorRed, err, colorReset)
			return
		}
		fmt.Printf("%sSource added successfully: %s%s\n", colorGreen, config.AddSource, colorReset)
		return
	}

	var configs []string
	var err error

	if config.Download {
		fmt.Printf("%sDownloading configs from online sources...%s\n", colorPurple, colorReset)
		configs, err = downloadConfigs()
		if err != nil {
			fmt.Printf("%sError downloading configs: %v%s\n", colorRed, err, colorReset)
			return
		}
		fmt.Printf("%sDownloaded %d configs%s\n", colorGreen, len(configs), colorReset)
	} else {
		configs, err = readConfigs(config.ConfigFile)
		if err != nil {
			fmt.Printf("%sError reading configs: %v%s\n", colorRed, err, colorReset)
			return
		}
	}

	if config.Limit > 0 && len(configs) > config.Limit {
		configs = configs[:config.Limit]
		fmt.Printf("%sLimited to %d configs%s\n", colorYellow, config.Limit, colorReset)
	}

	if len(configs) == 0 {
		fmt.Printf("%sNo configs found%s\n", colorRed, colorReset)
		return
	}

	xrayPath, err := getXrayBinary()
	if err != nil {
		fmt.Printf("%sError getting xray binary: %v%s\n", colorRed, err, colorReset)
		return
	}

	if config.Threads <= 0 {
		config.Threads = 4
	}
	if config.Timeout <= 0 {
		config.Timeout = 8
	}

	outputFile := config.OutputFile
	if outputFile == "" {
		outputFile = "alive_configs.txt"
	}
	_ = os.WriteFile(outputFile, nil, 0644)

	if config.RegionSort {
		if config.RegionDir == "" {
			config.RegionDir = "regions"
		}
		_ = os.MkdirAll(config.RegionDir, 0755)
	}

	fmt.Printf("%sLoaded %d configs%s\n", colorBlue, len(configs), colorReset)
	fmt.Printf("%sUsing xray binary: %s%s\n", colorCyan, xrayPath, colorReset)
	fmt.Printf("%sThreads: %d, Timeout: %.1fs%s\n", colorCyan, config.Threads, config.Timeout, colorReset)
	fmt.Printf("\n%sTesting configs...%s\n\n", colorBold, colorReset)

	results := make([]TestResult, len(configs))
	printed := make([]bool, len(configs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)
	var mu sync.Mutex
	nextIndex := 0

	for i, cfg := range configs {
		wg.Add(1)
		go func(idx int, configStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := testConfig(xrayPath, configStr, idx, config.Timeout, config.TestURL)

			mu.Lock()
			results[idx] = result

			for nextIndex < len(results) && results[nextIndex].Config != "" {
				r := results[nextIndex]
				if r.Alive {
					appendAliveConfig(outputFile, r.Config)
					if config.RegionSort && r.Country != "" {
						appendAliveConfig(getRegionFile(config.RegionDir, r.Country), r.Config)
					}
					loc := ""
					if r.Country != "" {
						loc = fmt.Sprintf(" [%s", r.Country)
						if r.City != "" {
							loc += fmt.Sprintf(" - %s", r.City)
						}
						if r.ISP != "" {
							loc += fmt.Sprintf(" - %s", r.ISP)
						}
						loc += "]"
					}
					statusInfo := ""
					if r.StatusCode > 0 {
						statusInfo = fmt.Sprintf(" [HTTP %d]", r.StatusCode)
					}
					ipInfo := ""
					if r.PublicIP != "" {
						ipInfo = fmt.Sprintf(" [IP %s]", r.PublicIP)
					}
					fmt.Printf("%s[%d] ✓ ALIVE%s %s (%s) %.0fms%s%s%s\n", colorGreen, nextIndex, colorReset, r.Server, r.Protocol, r.Latency.Seconds()*1000, statusInfo, ipInfo, loc)
				} else {
					fmt.Printf("%s[%d] ✗ DEAD%s %s: %s\n", colorRed, nextIndex, colorReset, r.Server, r.ErrorMsg)
				}
				printed[nextIndex] = true
				nextIndex++
			}
			mu.Unlock()
		}(i, cfg)
	}

	wg.Wait()

	for i := 0; i < len(results); i++ {
		if printed[i] {
			continue
		}
		r := results[i]
		if r.Alive {
			fmt.Printf("%s[%d] ✓ ALIVE%s %s (%s) %.0fms\n", colorGreen, i, colorReset, r.Server, r.Protocol, r.Latency.Seconds()*1000)
		} else {
			fmt.Printf("%s[%d] ✗ DEAD%s %s: %s\n", colorRed, i, colorReset, r.Server, r.ErrorMsg)
		}
	}

	aliveCount := 0
	httpOK := 0
	countryStats := map[string]int{}
	for _, r := range results {
		if r.Alive {
			aliveCount++
			if r.StatusCode >= 200 && r.StatusCode < 400 {
				httpOK++
			}
			if r.Country != "" {
				countryStats[r.Country]++
			}
		}
	}

	fmt.Printf("\n%s=== SUMMARY ===%s\n", colorBold, colorReset)
	fmt.Printf("%sTotal: %d%s\n", colorBlue, len(results), colorReset)
	fmt.Printf("%sAlive: %d%s\n", colorGreen, aliveCount, colorReset)
	fmt.Printf("%sDead: %d%s\n", colorRed, len(results)-aliveCount, colorReset)
	if config.TestURL != "" {
		fmt.Printf("%sHTTP OK: %d%s\n", colorPurple, httpOK, colorReset)
	}
	if len(countryStats) > 0 {
		fmt.Printf("\n%s=== LOCATION STATS ===%s\n", colorPurple, colorReset)
		for country, count := range countryStats {
			fmt.Printf("%s%s: %d%s\n", colorCyan, country, count, colorReset)
		}
	}
	if aliveCount > 0 {
		fmt.Printf("\n%sAlive configs saved to: %s%s\n", colorGreen, outputFile, colorReset)
	}
}

func getRegionFile(regionDir, country string) string {
	if country == "" {
		country = "Unknown"
	}
	filename := strings.ToLower(country)
	filename = strings.ReplaceAll(filename, " ", "_")
	filename = strings.ReplaceAll(filename, "-", "_")
	return filepath.Join(regionDir, filename+".txt")
}

func addSourceToFile(source string) error {
	var sources []string
	if _, err := os.Stat(configFileName); err == nil {
		data, err := os.ReadFile(configFileName)
		if err != nil {
			return err
		}
		var cfg SourceConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		sources = cfg.Sources
	}
	for _, s := range sources {
		if s == source {
			return fmt.Errorf("source already exists")
		}
	}
	sources = append(sources, source)
	data, err := json.MarshalIndent(SourceConfig{Sources: sources}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFileName, data, 0644)
}

func getSources() []string {
	var sources []string
	if _, err := os.Stat(configFileName); err == nil {
		if data, err := os.ReadFile(configFileName); err == nil {
			var cfg SourceConfig
			if json.Unmarshal(data, &cfg) == nil {
				sources = cfg.Sources
			}
		}
	}
	if len(sources) == 0 {
		sources = defaultSources
	}
	return sources
}

func downloadConfigs() ([]string, error) {
	sources := getSources()
	var allConfigs []string
	seen := make(map[string]struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10)

	for _, source := range sources {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			client := &http.Client{Timeout: 12 * time.Second}
			resp, err := client.Get(u)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			scanner := bufio.NewScanner(bytes.NewReader(body))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				mu.Lock()
				if _, ok := seen[line]; !ok {
					seen[line] = struct{}{}
					allConfigs = append(allConfigs, line)
				}
				mu.Unlock()
			}
		}(source)
	}

	wg.Wait()
	return allConfigs, nil
}

func readConfigs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var configs []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			configs = append(configs, line)
		}
	}
	return configs, scanner.Err()
}

func appendAliveConfig(filename, config string) {
	appendMutex.Lock()
	defer appendMutex.Unlock()
	_ = os.MkdirAll(filepath.Dir(filename), 0755)
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(config + "\n")
}

func getXrayBinary() (string, error) {
	var xrayDir string
	if runtime.GOOS == "windows" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		xrayDir = filepath.Join(homeDir, ".xray-test")
	} else {
		xrayDir = filepath.Join(os.TempDir(), ".xray-test")
	}
	if err := os.MkdirAll(xrayDir, 0755); err != nil {
		return "", err
	}

	binaryName := "xray"
	if runtime.GOOS == "windows" {
		binaryName = "xray.exe"
	}

	xrayPath := filepath.Join(xrayDir, binaryName)
	if _, err := os.Stat(xrayPath); err == nil {
		return xrayPath, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(getDownloadURL())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return "", err
	}

	found := false
	for _, f := range zr.File {
		if f.Name == binaryName || f.Name == "xray.exe" || f.Name == "xray" {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			out, err := os.Create(xrayPath)
			if err != nil {
				rc.Close()
				return "", err
			}
			_, cErr := io.Copy(out, rc)
			rc.Close()
			out.Close()
			if cErr != nil {
				return "", cErr
			}
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("binary not found in zip")
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(xrayPath, 0755)
	}
	return xrayPath, nil
}

func getDownloadURL() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	if osName == "darwin" {
		osName = "macos"
	}
	switch arch {
	case "amd64":
		arch = "64"
	case "arm64":
		arch = "arm64-v8a"
	case "386":
		arch = "32"
	}
	return fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-%s-%s.zip", osName, arch)
}

func testConfig(xrayPath string, config string, index int, timeoutSec float64, testURL string) TestResult {
	result := TestResult{
		Index:    index,
		Config:   config,
		Alive:    false,
		Protocol: detectProtocol(config),
		Server:   "unknown",
	}

	server := extractServer(config)
	if server != "" {
		result.Server = server
		geo := getGeoLocation(server)
		result.Country = geo.Country
		result.City = geo.City
		result.ISP = geo.ISP
	}

	cfgFile, port, err := createXrayConfigFromLink(config)
	if err != nil {
		result.ErrorMsg = err.Error()
		return result
	}
	defer os.Remove(cfgFile)

	timeoutDuration := time.Duration(timeoutSec*1000) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration+20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, xrayPath, "run", "-c", cfgFile)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		result.ErrorMsg = fmt.Sprintf("start error: %v", err)
		return result
	}

	if !waitForSOCKS5Ready(port, 40, 200*time.Millisecond) {
		killProcess(cmd)
		result.ErrorMsg = "socks5 not ready"
		return result
	}

	targets := aliveTargets
	if testURL != "" {
		targets = []string{testURL}
	}

	httpOK, statusCode := checkHTTPProxy(port, timeoutSec, targets)
	if httpOK {
		result.Alive = true
		result.Latency = time.Since(start)
		result.StatusCode = statusCode

		if ip, ipStatus, ok := probePublicIP(port, timeoutSec); ok {
			result.PublicIP = ip
			if result.StatusCode == 0 {
				result.StatusCode = ipStatus
			}
		}
	} else {
		result.ErrorMsg = parseErr(stderr.String())
		if result.ErrorMsg == "" {
			result.ErrorMsg = "proxy check failed"
		}
		if statusCode > 0 {
			result.StatusCode = statusCode
		}
	}

	killProcess(cmd)
	return result
}

func detectProtocol(config string) string {
	switch {
	case strings.HasPrefix(config, "vless://"):
		return "vless"
	case strings.HasPrefix(config, "vmess://"):
		return "vmess"
	case strings.HasPrefix(config, "trojan://"):
		return "trojan"
	case strings.HasPrefix(config, "ss://"):
		return "ss"
	default:
		return "unknown"
	}
}

func parseErr(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		l := strings.ToLower(line)
		if strings.Contains(l, "error") || strings.Contains(l, "failed") || strings.Contains(l, "refused") || strings.Contains(l, "timeout") || strings.Contains(l, "dial") || strings.Contains(l, "uuid") {
			return line
		}
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

func killProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func waitForSOCKS5Ready(port int, maxAttempts int, delay time.Duration) bool {
	for i := 0; i < maxAttempts; i++ {
		if checkSOCKS5Ready(port) {
			return true
		}
		time.Sleep(delay)
	}
	return false
}

func checkSOCKS5Ready(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 600*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return false
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return buf[0] == 0x05 && buf[1] == 0x00
}

func extractServer(config string) string {
	switch {
	case strings.HasPrefix(config, "vmess://"):
		encoded := strings.TrimPrefix(config, "vmess://")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil {
			return ""
		}
		var v VMessConfig
		if err := json.Unmarshal(decoded, &v); err != nil {
			return ""
		}
		return v.Add
	case strings.HasPrefix(config, "ss://"):
		return extractSSServer(config)
	default:
		if u, err := url.Parse(config); err == nil {
			return u.Hostname()
		}
		return ""
	}
}

func extractSSServer(link string) string {
	s := strings.TrimPrefix(link, "ss://")
	if i := strings.IndexAny(s, "#?"); i >= 0 {
		s = s[:i]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		return stripHostPort(s[at+1:])
	}
	decoded, err := base64.RawStdEncoding.DecodeString(stripPadding(s))
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(stripPadding(s))
	}
	if err != nil {
		return ""
	}
	raw := string(decoded)
	at := strings.LastIndex(raw, "@")
	if at < 0 {
		return ""
	}
	return stripHostPort(raw[at+1:])
}

func stripPadding(s string) string {
	return strings.TrimRight(s, "=")
}

func isValidUUIDString(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func createXrayConfigFromLink(link string) (string, int, error) {
	if strings.HasPrefix(link, "vmess://") {
		return createVMessConfig(link)
	}
	if strings.HasPrefix(link, "ss://") {
		return createSSConfig(link)
	}

	port, err := getFreePort()
	if err != nil {
		return "", 0, err
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse link: %v", err)
	}

	protocol := u.Scheme
	host := u.Hostname()
	serverPort := 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			serverPort = n
		}
	}

	userID := ""
	if u.User != nil {
		userID = u.User.Username()
		if userID == "" {
			userID, _ = u.User.Password()
		}
	}

	if protocol != "trojan" && !isValidUUIDString(userID) {
		return "", 0, fmt.Errorf("invalid UUID: %s", userID)
	}

	q := u.Query()
	security := q.Get("security")
	if security == "" {
		security = "none"
	}
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	path := q.Get("path")
	if path == "" {
		path = "/"
	}
	hostHeader := q.Get("host")
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("serverName")
	}
	pbk := q.Get("pbk")
	if pbk == "" {
		pbk = q.Get("publicKey")
	}
	sid := q.Get("sid")
	if sid == "" {
		sid = q.Get("shortId")
	}
	serviceName := q.Get("serviceName")
	flow := q.Get("flow")
	encryption := q.Get("encryption")
	if encryption == "" {
		encryption = "none"
	}
	fingerprint := q.Get("fp")
	if fingerprint == "" {
		fingerprint = q.Get("fingerprint")
	}
	alpn := q.Get("alpn")
	headerType := q.Get("headerType")
	allowInsecure := q.Get("allowInsecure") == "true"

	outbound := map[string]any{
		"protocol": "freedom",
		"tag":      "direct",
	}
	proxyOutbound := map[string]any{
		"protocol": protocol,
		"tag":      "proxy",
		"settings": map[string]any{},
		"streamSettings": map[string]any{
			"network":  network,
			"security": security,
		},
	}

	switch protocol {
	case "vless":
		user := map[string]any{"id": userID, "encryption": encryption}
		if flow != "" {
			user["flow"] = flow
		}
		proxyOutbound["settings"] = map[string]any{
			"vnext": []map[string]any{
				{"address": host, "port": serverPort, "users": []map[string]any{user}},
			},
		}
	case "vmess":
		user := map[string]any{"id": userID, "security": "auto"}
		proxyOutbound["settings"] = map[string]any{
			"vnext": []map[string]any{
				{"address": host, "port": serverPort, "users": []map[string]any{user}},
			},
		}
	case "trojan":
		proxyOutbound["settings"] = map[string]any{
			"servers": []map[string]any{
				{"address": host, "port": serverPort, "password": userID},
			},
		}
	}

	stream := proxyOutbound["streamSettings"].(map[string]any)

	switch network {
	case "ws":
		ws := map[string]any{"path": path}
		if hostHeader != "" {
			ws["headers"] = map[string]string{"Host": hostHeader}
		}
		stream["wsSettings"] = ws
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": serviceName}
	case "h2":
		stream["httpSettings"] = map[string]any{"path": path}
	case "httpupgrade":
		hs := map[string]any{"path": path}
		if hostHeader != "" {
			hs["host"] = hostHeader
		}
		stream["httpupgradeSettings"] = hs
	case "splithttp":
		hs := map[string]any{"path": path}
		if hostHeader != "" {
			hs["host"] = hostHeader
		}
		stream["splithttpSettings"] = hs
	case "quic":
		stream["quicSettings"] = map[string]any{"security": security, "key": pbk}
	case "kcp":
		stream["kcpSettings"] = map[string]any{"header": map[string]any{"type": headerType}}
	case "tcp":
		if headerType != "" && headerType != "none" {
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": headerType}}
		}
	}

	if security == "tls" {
		tls := map[string]any{"serverName": sni}
		if fingerprint != "" {
			tls["fingerprint"] = fingerprint
		}
		if alpn != "" {
			tls["alpn"] = splitCSV(alpn)
		}
		if allowInsecure {
			tls["allowInsecure"] = true
		}
		stream["tlsSettings"] = tls
	} else if security == "reality" {
		reality := map[string]any{
			"serverName": sni,
			"publicKey":  pbk,
			"shortId":    sid,
		}
		if fingerprint != "" {
			reality["fingerprint"] = fingerprint
		}
		if alpn != "" {
			reality["alpn"] = splitCSV(alpn)
		}
		stream["realitySettings"] = reality
	}

	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": map[string]any{"servers": []string{"1.1.1.1", "8.8.8.8"}},
		"inbounds": []map[string]any{
			{
				"port":    port,
				"listen":  "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": true},
			},
		},
		"outbounds": []map[string]any{proxyOutbound, outbound},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", 0, err
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%d_%d.json", time.Now().UnixNano(), os.Getpid()))
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return "", 0, err
	}
	return tmp, port, nil
}

func createSSConfig(link string) (string, int, error) {
	port, err := getFreePort()
	if err != nil {
		return "", 0, err
	}

	ssLink := strings.TrimPrefix(link, "ss://")
	if i := strings.IndexAny(ssLink, "#?"); i >= 0 {
		ssLink = ssLink[:i]
	}

	var method, password, hostPart string
	if at := strings.LastIndex(ssLink, "@"); at >= 0 {
		authPart := ssLink[:at]
		hostPart = ssLink[at+1:]
		if dec, err := decodeSSAuth(authPart); err == nil {
			method, password = dec[0], dec[1]
		} else {
			parts := strings.SplitN(authPart, ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		}
	} else {
		dec, err := decodeSSAuth(ssLink)
		if err != nil {
			return "", 0, fmt.Errorf("invalid ss format")
		}
		method, password, hostPart = dec[0], dec[1], dec[2]
	}

	if method == "" || hostPart == "" {
		return "", 0, fmt.Errorf("invalid ss format")
	}

	host, serverPort := parseSSHostPort(hostPart)
	if serverPort <= 0 {
		serverPort = 443
	}

	proxyOutbound := map[string]any{
		"protocol": "shadowsocks",
		"tag":      "proxy",
		"settings": map[string]any{
			"servers": []map[string]any{
				{"address": host, "port": serverPort, "method": method, "password": password},
			},
		},
		"streamSettings": map[string]any{"network": "tcp", "security": "none"},
	}

	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": map[string]any{"servers": []string{"1.1.1.1", "8.8.8.8"}},
		"inbounds": []map[string]any{
			{
				"port":    port,
				"listen":  "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": true},
			},
		},
		"outbounds": []map[string]any{proxyOutbound},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", 0, err
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%d_%d.json", time.Now().UnixNano(), os.Getpid()))
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return "", 0, err
	}
	return tmp, port, nil
}

func parseSSHostPort(hostPart string) (string, int) {
	hostPart = strings.TrimSpace(hostPart)
	if i := strings.IndexAny(hostPart, "#?"); i >= 0 {
		hostPart = hostPart[:i]
	}
	if strings.HasPrefix(hostPart, "[") {
		end := strings.Index(hostPart, "]")
		if end > 0 {
			host := hostPart[1:end]
			p := 0
			if len(hostPart) > end+1 && hostPart[end+1] == ':' {
				p, _ = strconv.Atoi(hostPart[end+2:])
			}
			return host, p
		}
	}
	if h, p, err := net.SplitHostPort(hostPart); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	if i := strings.LastIndex(hostPart, ":"); i > 0 && !strings.Contains(hostPart[i+1:], ":") {
		n, _ := strconv.Atoi(hostPart[i+1:])
		return hostPart[:i], n
	}
	return hostPart, 0
}

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func checkHTTPProxy(port int, timeoutSec float64, testURLs []string) (bool, int) {
	timeout := time.Duration(timeoutSec*1000) * time.Millisecond

	auth := proxy.Auth{}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &auth, proxy.Direct)
	if err != nil {
		return false, 0
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout:  timeout,
		IdleConnTimeout:       5 * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	type res struct {
		ok   bool
		code int
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan res, len(testURLs))

	for _, u := range testURLs {
		go func(target string) {
			reqCtx, reqCancel := context.WithTimeout(ctx, timeout)
			defer reqCancel()

			req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, target, nil)
			if err != nil {
				ch <- res{}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err == nil && resp != nil && resp.StatusCode == http.StatusMethodNotAllowed {
				resp.Body.Close()

				req2, err2 := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
				if err2 != nil {
					ch <- res{}
					return
				}
				req2.Header.Set("User-Agent", "Mozilla/5.0")
				resp, err = client.Do(req2)
			}

			if err != nil || resp == nil {
				ch <- res{}
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				ch <- res{ok: true, code: resp.StatusCode}
				return
			}
			ch <- res{code: resp.StatusCode}
		}(u)
	}

	bestCode := 0
	for range testURLs {
		r := <-ch
		if r.code > 0 && bestCode == 0 {
			bestCode = r.code
		}
		if r.ok {
			cancel()
			return true, r.code
		}
	}

	return false, bestCode
}

func probePublicIP(port int, timeoutSec float64) (string, int, bool) {
	timeout := time.Duration(timeoutSec*1000) * time.Millisecond
	auth := proxy.Auth{}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &auth, proxy.Direct)
	if err != nil {
		return "", 0, false
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		ForceAttemptHTTP2:    true,
		TLSHandshakeTimeout:  timeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:      5 * time.Second,
		DisableKeepAlives:    true,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	for _, endpoint := range publicIPChecks {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(body))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "{") {
			var m map[string]any
			if json.Unmarshal(body, &m) == nil {
				if ip, ok := m["ip"].(string); ok && ip != "" {
					return ip, resp.StatusCode, true
				}
				if ip, ok := m["origin"].(string); ok && ip != "" {
					return ip, resp.StatusCode, true
				}
			}
			continue
		}
		return s, resp.StatusCode, true
	}
	return "", 0, false
}

func stripHostPort(hostPart string) string {
	hostPart = strings.TrimSpace(hostPart)
	if i := strings.IndexAny(hostPart, "#?"); i >= 0 {
		hostPart = hostPart[:i]
	}
	if strings.HasPrefix(hostPart, "[") {
		if end := strings.Index(hostPart, "]"); end > 0 {
			return hostPart[1:end]
		}
	}
	if h, _, err := net.SplitHostPort(hostPart); err == nil {
		return h
	}
	if i := strings.LastIndex(hostPart, ":"); i > 0 && !strings.Contains(hostPart[i+1:], ":") {
		return hostPart[:i]
	}
	return hostPart
}

func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func createVMessConfig(link string) (string, int, error) {
	port, err := getFreePort()
	if err != nil {
		return "", 0, err
	}

	encoded := strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode vmess: %v", err)
	}

	var v VMessConfig
	if err := json.Unmarshal(decoded, &v); err != nil {
		return "", 0, fmt.Errorf("failed to parse vmess json: %v", err)
	}
	if !isValidUUID(v.ID) {
		return "", 0, fmt.Errorf("invalid UUID in vmess config")
	}

	serverPort := 443
	if n, err := strconv.Atoi(v.Port); err == nil && n > 0 {
		serverPort = n
	}

	network := v.Net
	if network == "" {
		network = "tcp"
	}
	security := v.TLS
	if security == "" {
		security = "none"
	}
	if security == "xtls" {
		security = "tls"
	}
	path := v.Path
	if path == "" {
		path = "/"
	}
	sni := v.Sni
	if sni == "" {
		sni = v.Add
	}

	proxyOutbound := map[string]any{
		"protocol": "vmess",
		"tag":      "proxy",
		"settings": map[string]any{
			"vnext": []map[string]any{
				{
					"address": v.Add,
					"port":    serverPort,
					"users": []map[string]any{
						{"id": v.ID, "security": "auto"},
					},
				},
			},
		},
		"streamSettings": map[string]any{
			"network":  network,
			"security": security,
		},
	}

	stream := proxyOutbound["streamSettings"].(map[string]any)
	switch network {
	case "ws":
		ws := map[string]any{"path": path}
		if v.Host != "" {
			ws["headers"] = map[string]string{"Host": v.Host}
		}
		stream["wsSettings"] = ws
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": path}
	case "h2":
		stream["httpSettings"] = map[string]any{"path": path}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{"path": path}
	case "splithttp":
		stream["splithttpSettings"] = map[string]any{"path": path}
	case "quic":
		stream["quicSettings"] = map[string]any{"security": "none"}
	case "kcp":
		stream["kcpSettings"] = map[string]any{"header": map[string]any{"type": v.Type}}
	case "tcp":
		if v.Type != "" && v.Type != "none" && v.Type != "http" {
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": v.Type}}
		}
	}

	if security == "tls" {
		tls := map[string]any{"serverName": sni}
		if v.Fingerprint != "" {
			tls["fingerprint"] = v.Fingerprint
		}
		if v.Alpn != "" {
			tls["alpn"] = splitCSV(v.Alpn)
		}
		stream["tlsSettings"] = tls
	}

	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": map[string]any{"servers": []string{"1.1.1.1", "8.8.8.8"}},
		"inbounds": []map[string]any{
			{
				"port":     port,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]any{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []map[string]any{
			proxyOutbound,
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", 0, err
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%d_%d.json", time.Now().UnixNano(), os.Getpid()))
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return "", 0, err
	}
	return tmp, port, nil
}

func decodeSSAuth(s string) ([3]string, error) {
	var out [3]string
	raw := strings.TrimRight(s, "=")
	dec, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		dec, err = base64.StdEncoding.DecodeString(raw)
	}
	if err != nil {
		return out, err
	}
	parts := strings.SplitN(string(dec), "@", 2)
	if len(parts) != 2 {
		return out, fmt.Errorf("invalid ss auth")
	}
	up := strings.SplitN(parts[0], ":", 2)
	if len(up) != 2 {
		return out, fmt.Errorf("invalid ss auth")
	}
	out[0] = up[0]
	out[1] = up[1]
	out[2] = parts[1]
	return out, nil
}

func getGeoLocation(target string) GeoInfo {
	cacheMutex.Lock()
	if cached, ok := geoCache[target]; ok {
		cacheMutex.Unlock()
		return cached
	}
	cacheMutex.Unlock()

	host := target
	if ips, err := net.LookupIP(target); err == nil && len(ips) > 0 {
		host = ips[0].String()
	}

	client := &http.Client{Timeout: 4 * time.Second}
	var geo GeoInfo

	for i := 0; i < len(geoAPIs); i++ {
		apiIndex := (geoFallback + i) % len(geoAPIs)
		resp, err := client.Get(fmt.Sprintf(geoAPIs[apiIndex], host))
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var raw map[string]any
		if json.Unmarshal(body, &raw) != nil {
			continue
		}

		if apiIndex == 0 {
			if status, _ := raw["status"].(string); status == "success" {
				geo.Status = status
				geo.Country, _ = raw["country"].(string)
				geo.City, _ = raw["city"].(string)
				geo.ISP, _ = raw["isp"].(string)
				geo.Org, _ = raw["org"].(string)
				geo.CountryCode, _ = raw["countryCode"].(string)
				if geo.Country != "" {
					geoFallback = apiIndex
					break
				}
			} else if msg, _ := raw["message"].(string); strings.Contains(strings.ToLower(msg), "rate limited") {
				geoFallback = (apiIndex + 1) % len(geoAPIs)
			}
		} else {
			if country, ok := raw["country"].(string); ok && country != "" {
				geo.Status = "success"
				geo.Country = country
				geo.City, _ = raw["city"].(string)
				geo.Org, _ = raw["org"].(string)
				geo.ISP = geo.Org
				if cc, ok := raw["countryCode"].(string); ok {
					geo.CountryCode = cc
				}
				geoFallback = apiIndex
				break
			}
		}
	}

	cacheMutex.Lock()
	geoCache[target] = geo
	cacheMutex.Unlock()
	return geo
}

func splitCSV(s string) []string {
	ps := strings.Split(s, ",")
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
