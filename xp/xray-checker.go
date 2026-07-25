package xp

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
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
)

type XrayConfig struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}

type Inbound struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Settings struct {
		Clients []struct {
			ID string `json:"id"`
		} `json:"clients"`
	} `json:"settings"`
	StreamSettings struct {
		Network      string `json:"network"`
		Security     string `json:"security"`
		WSSettings   struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"wsSettings"`
		GRPCSettings struct {
			ServiceName string `json:"serviceName"`
		} `json:"grpcSettings"`
		RealitySettings struct {
			ServerName string `json:"serverName"`
			PublicKey  string `json:"publicKey"`
			ShortID    string `json:"shortId"`
		} `json:"realitySettings"`
		TCPSettings struct {
			Header struct {
				Type string `json:"type"`
			} `json:"header"`
		} `json:"tcpSettings"`
	} `json:"streamSettings"`
}

type Outbound struct {
	Protocol string `json:"protocol"`
	Settings struct {
		VNext []struct {
			Address string `json:"address"`
			Port    int    `json:"port"`
			Users   []struct {
				ID         string `json:"id"`
				Flow       string `json:"flow"`
				Encryption string `json:"encryption"`
			} `json:"users"`
		} `json:"vnext"`
		Servers []struct {
			Address  string `json:"address"`
			Port     int    `json:"port"`
			Password string `json:"password"`
		} `json:"servers"`
	} `json:"settings"`
	StreamSettings struct {
		Network      string `json:"network"`
		Security     string `json:"security"`
		WSSettings   struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"wsSettings"`
		GRPCSettings struct {
			ServiceName string `json:"serviceName"`
		} `json:"grpcSettings"`
		RealitySettings struct {
			ServerName string `json:"serverName"`
			PublicKey  string `json:"publicKey"`
			ShortID    string `json:"shortId"`
		} `json:"realitySettings"`
		TCPSettings struct {
			Header struct {
				Type string `json:"type"`
			} `json:"header"`
		} `json:"tcpSettings"`
	} `json:"streamSettings"`
}

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

var configFileName = "sources.json"

var geoCache = make(map[string]GeoInfo)
var cacheMutex sync.Mutex
var geoAPIFallback = 0

func RunChecker(config CheckerConfig) {
	if config.AddSource != "" {
		err := addSourceToFile(config.AddSource)
		if err != nil {
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

	fmt.Printf("%sLoaded %d configs%s\n", colorBlue, len(configs), colorReset)

	xrayPath, err := getXrayBinary()
	if err != nil {
		fmt.Printf("%sError getting xray binary: %v%s\n", colorRed, err, colorReset)
		return
	}

	fmt.Printf("%sUsing xray binary: %s%s\n", colorCyan, xrayPath, colorReset)

	if config.Threads == 0 {
		config.Threads = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 0.5
	}
	fmt.Printf("%sThreads: %d, Timeout: %.1fs%s\n", colorCyan, config.Threads, config.Timeout, colorReset)

	outputFile := config.OutputFile
	if outputFile == "" {
		outputFile = "alive_configs.txt"
	}

	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("%sError creating alive file: %v%s\n", colorRed, err, colorReset)
		return
	}
	f.Close()

	results := make([]TestResult, len(configs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)
	var mu sync.Mutex

	fmt.Printf("\n%sTesting configs...%s\n\n", colorBold, colorReset)

	for i, cfg := range configs {
		wg.Add(1)
		go func(idx int, configStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result := testConfig(xrayPath, configStr, idx, config.Timeout, config.TestURL)
			results[idx] = result

			mu.Lock()
			if result.Alive {
				appendAliveConfig(outputFile, configStr)
				location := ""
				if result.Country != "" {
					location = fmt.Sprintf(" [%s", result.Country)
					if result.City != "" {
						location += fmt.Sprintf(" - %s", result.City)
					}
					if result.ISP != "" {
						location += fmt.Sprintf(" - %s", result.ISP)
					}
					location += "]"
				}
				statusInfo := ""
				if result.StatusCode > 0 {
					statusInfo = fmt.Sprintf(" [HTTP %d]", result.StatusCode)
				}
				fmt.Printf("%s[%d] %s✓ ALIVE%s %s(%s) %.0fms%s%s%s\n",
					colorGreen, idx, colorGreen, colorReset,
					result.Server, result.Protocol, result.Latency.Seconds()*1000,
					statusInfo, colorWhite, location)
			} else {
				fmt.Printf("%s[%d] %s✗ DEAD%s %s: %s%s\n",
					colorRed, idx, colorRed, colorReset,
					result.Server, result.ErrorMsg, colorReset)
			}
			mu.Unlock()
		}(i, cfg)
	}

	wg.Wait()

	fmt.Printf("\n%s=== SUMMARY ===%s\n", colorBold, colorReset)
	aliveCount := 0
	httpSuccessCount := 0
	countryStats := make(map[string]int)

	for _, result := range results {
		if result.Alive {
			aliveCount++
			if result.StatusCode >= 200 && result.StatusCode < 400 {
				httpSuccessCount++
			}
			if result.Country != "" {
				countryStats[result.Country]++
			}
		}
	}

	fmt.Printf("%sTotal: %d%s\n", colorBlue, len(configs), colorReset)
	fmt.Printf("%sAlive: %d%s\n", colorGreen, aliveCount, colorReset)
	fmt.Printf("%sDead: %d%s\n", colorRed, len(configs)-aliveCount, colorReset)

	if config.TestURL != "" {
		fmt.Printf("%sHTTP OK: %d%s\n", colorPurple, httpSuccessCount, colorReset)
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

func getGeoLocation(ip string) GeoInfo {
	cacheMutex.Lock()
	if cached, ok := geoCache[ip]; ok {
		cacheMutex.Unlock()
		return cached
	}
	cacheMutex.Unlock()

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	var geo GeoInfo

	for i := 0; i < len(geoAPIs); i++ {
		apiIndex := (geoAPIFallback + i) % len(geoAPIs)
		apiURL := fmt.Sprintf(geoAPIs[apiIndex], ip)

		resp, err := client.Get(apiURL)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var raw map[string]interface{}
		err = json.Unmarshal(body, &raw)
		if err != nil {
			continue
		}

		if apiIndex == 0 {
			if status, ok := raw["status"].(string); ok && status == "success" {
				geo.Status = "success"
				if country, ok := raw["country"].(string); ok {
					geo.Country = country
				}
				if city, ok := raw["city"].(string); ok {
					geo.City = city
				}
				if isp, ok := raw["isp"].(string); ok {
					geo.ISP = isp
				}
				if org, ok := raw["org"].(string); ok {
					geo.Org = org
				}
				if code, ok := raw["countryCode"].(string); ok {
					geo.CountryCode = code
				}

				if geo.Country != "" {
					geoAPIFallback = apiIndex
					break
				}
			} else if msg, ok := raw["message"].(string); ok && strings.Contains(msg, "rate limited") {
				geoAPIFallback = (apiIndex + 1) % len(geoAPIs)
				continue
			}
		} else if apiIndex == 1 {
			if country, ok := raw["country"].(string); ok {
				geo.Status = "success"
				geo.Country = country
				if city, ok := raw["city"].(string); ok {
					geo.City = city
				}
				if org, ok := raw["org"].(string); ok {
					geo.ISP = org
				}
				if code, ok := raw["country"].(string); ok {
					if len(code) >= 2 {
						geo.CountryCode = code[:2]
					}
				}
				geoAPIFallback = apiIndex
				break
			}
		}
	}

	cacheMutex.Lock()
	geoCache[ip] = geo
	cacheMutex.Unlock()

	return geo
}

func addSourceToFile(source string) error {
	var sources []string

	if _, err := os.Stat(configFileName); err == nil {
		data, err := os.ReadFile(configFileName)
		if err != nil {
			return err
		}
		var config SourceConfig
		err = json.Unmarshal(data, &config)
		if err != nil {
			return err
		}
		sources = config.Sources
	}

	for _, s := range sources {
		if s == source {
			return fmt.Errorf("source already exists")
		}
	}

	sources = append(sources, source)

	config := SourceConfig{Sources: sources}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFileName, data, 0644)
}

func getSources() []string {
	var sources []string

	if _, err := os.Stat(configFileName); err == nil {
		data, err := os.ReadFile(configFileName)
		if err == nil {
			var config SourceConfig
			err = json.Unmarshal(data, &config)
			if err == nil {
				sources = config.Sources
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
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, source := range sources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			client := &http.Client{
				Timeout: 10 * time.Second,
			}

			resp, err := client.Get(url)
			if err != nil {
				fmt.Printf("%sFailed to download %s: %v%s\n", colorRed, url, err, colorReset)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				fmt.Printf("%sFailed to download %s (status: %d)%s\n", colorRed, url, resp.StatusCode, colorReset)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("%sFailed to read %s: %v%s\n", colorRed, url, err, colorReset)
				return
			}

			scanner := bufio.NewScanner(bytes.NewReader(body))
			var count int
			configsSet := make(map[string]bool)

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					if !configsSet[line] {
						mu.Lock()
						allConfigs = append(allConfigs, line)
						configsSet[line] = true
						count++
						mu.Unlock()
					}
				}
			}
			fmt.Printf("%sDownloaded %d configs from %s%s\n", colorCyan, count, url, colorReset)
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
	configsSet := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !configsSet[line] {
				configs = append(configs, line)
				configsSet[line] = true
			}
		}
	}
	return configs, scanner.Err()
}

func appendAliveConfig(filename, config string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(config + "\n")
}

func getXrayBinary() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	xrayDir := filepath.Join(homeDir, ".xray-test")
	if err := os.MkdirAll(xrayDir, 0755); err != nil {
		return "", err
	}

	var binaryName string
	if runtime.GOOS == "windows" {
		binaryName = "xray.exe"
	} else {
		binaryName = "xray"
	}

	xrayPath := filepath.Join(xrayDir, binaryName)

	if _, err := os.Stat(xrayPath); err == nil {
		fmt.Printf("%sXray binary already exists%s\n", colorGreen, colorReset)
		return xrayPath, nil
	}

	fmt.Printf("%sDownloading xray binary for %s/%s...%s\n", colorYellow, runtime.GOOS, runtime.GOARCH, colorReset)

	url := getDownloadURL()
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(url)
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

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return "", err
	}

	found := false
	for _, file := range zipReader.File {
		if file.Name == binaryName || file.Name == "xray.exe" || file.Name == "xray" {
			rc, err := file.Open()
			if err != nil {
				return "", err
			}
			defer rc.Close()

			outFile, err := os.Create(xrayPath)
			if err != nil {
				return "", err
			}
			defer outFile.Close()

			_, err = io.Copy(outFile, rc)
			if err != nil {
				return "", err
			}
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("binary not found in zip")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(xrayPath, 0755); err != nil {
			return "", err
		}
	}

	fmt.Printf("%sXray binary downloaded successfully%s\n", colorGreen, colorReset)
	return xrayPath, nil
}

func getDownloadURL() string {
	os := runtime.GOOS
	arch := runtime.GOARCH

	if os == "darwin" {
		os = "macos"
	}

	if arch == "amd64" {
		arch = "64"
	} else if arch == "arm64" {
		arch = "arm64-v8a"
	} else if arch == "386" {
		arch = "32"
	}

	return fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-%s-%s.zip", os, arch)
}

func testConfig(xrayPath string, config string, index int, timeoutSec float64, testURL string) TestResult {
	result := TestResult{
		Index:  index,
		Config: config,
		Alive:  false,
	}

	parsed, err := parseConfig(config)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("parse error: %v", err)
		result.Server = "unknown"
		return result
	}

	result.Server = parsed.Hostname()
	result.Protocol = parsed.Scheme
	result.Network = parsed.Query().Get("type")
	if result.Network == "" {
		result.Network = "tcp"
	}

	geo := getGeoLocation(result.Server)
	result.Country = geo.Country
	result.City = geo.City
	result.ISP = geo.ISP

	cfgFile, err := createXrayConfig(parsed)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("config error: %v", err)
		return result
	}
	defer os.Remove(cfgFile)

	timeoutDuration := time.Duration(timeoutSec*1000) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration+5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, xrayPath, "run", "-c", cfgFile)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	start := time.Now()
	err = cmd.Start()
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("start error: %v", err)
		return result
	}

	time.Sleep(timeoutDuration)

	alive := false
	if testURL != "" {
		alive, result.StatusCode = checkHTTPProxy(parsed, timeoutSec, testURL)
	} else {
		alive = checkTCPProxy(parsed, timeoutSec)
	}

	if alive {
		result.Alive = true
		result.Latency = time.Since(start)
	} else {
		if testURL != "" {
			result.ErrorMsg = fmt.Sprintf("HTTP test failed (status: %d)", result.StatusCode)
		} else {
			result.ErrorMsg = "not responding"
		}
	}

	cmd.Process.Kill()
	cmd.Wait()

	return result
}

func parseConfig(link string) (*url.URL, error) {
	if !strings.Contains(link, "://") {
		return nil, fmt.Errorf("invalid config format")
	}

	parts := strings.SplitN(link, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid config format")
	}

	protocol := parts[0]
	rest := parts[1]

	atIndex := strings.Index(rest, "@")
	if atIndex == -1 {
		return nil, fmt.Errorf("missing @ in config")
	}

	userInfo := rest[:atIndex]
	hostPart := rest[atIndex+1:]

	questionIndex := strings.Index(hostPart, "?")
	var host string
	var query string
	if questionIndex == -1 {
		host = hostPart
	} else {
		host = hostPart[:questionIndex]
		query = hostPart[questionIndex+1:]
	}

	hashIndex := strings.Index(host, "#")
	if hashIndex != -1 {
		host = host[:hashIndex]
	}

	fullURL := fmt.Sprintf("%s://%s@%s", protocol, userInfo, host)
	if query != "" {
		fullURL += "?" + query
	}

	return url.Parse(fullURL)
}

func createXrayConfig(parsed *url.URL) (string, error) {
	config := XrayConfig{}

	port, err := getFreePort()
	if err != nil {
		return "", err
	}

	protocol := parsed.Scheme

	serverAddr := parsed.Hostname()
	serverPort := 443
	if parsed.Port() != "" {
		serverPort, _ = strconv.Atoi(parsed.Port())
	}

	userInfo := parsed.User
	var userID string
	if userInfo != nil {
		userID = userInfo.Username()
	}
	if userID == "" {
		userID = "00000000-0000-0000-0000-000000000000"
	}

	query := parsed.Query()
	security := query.Get("security")
	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}
	path := query.Get("path")
	if path == "" {
		path = "/"
	}
	hostHeader := query.Get("host")
	sni := query.Get("sni")
	pbk := query.Get("pbk")
	sid := query.Get("sid")
	serviceName := query.Get("serviceName")
	flow := query.Get("flow")
	encryption := query.Get("encryption")
	if encryption == "" {
		encryption = "none"
	}
	mode := query.Get("mode")

	inbound := Inbound{
		Port:     port,
		Protocol: "socks",
	}
	inbound.Settings.Clients = append(inbound.Settings.Clients, struct {
		ID string `json:"id"`
	}{ID: userID})
	inbound.StreamSettings.Network = "tcp"
	inbound.StreamSettings.Security = "none"

	config.Inbounds = append(config.Inbounds, inbound)

	outbound := Outbound{
		Protocol: protocol,
	}
	outbound.StreamSettings.Network = network
	outbound.StreamSettings.Security = security

	if network == "ws" {
		outbound.StreamSettings.WSSettings.Path = path
		if hostHeader != "" {
			outbound.StreamSettings.WSSettings.Headers = map[string]string{"Host": hostHeader}
		}
	}

	if network == "grpc" {
		outbound.StreamSettings.GRPCSettings.ServiceName = serviceName
		if mode == "gun" {
		}
	}

	if security == "reality" {
		outbound.StreamSettings.RealitySettings.ServerName = sni
		outbound.StreamSettings.RealitySettings.PublicKey = pbk
		outbound.StreamSettings.RealitySettings.ShortID = sid
	}

	if network == "tcp" && security == "reality" {
		outbound.StreamSettings.TCPSettings.Header.Type = "none"
	}

	outbound.Settings.VNext = append(outbound.Settings.VNext, struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Users   []struct {
			ID         string `json:"id"`
			Flow       string `json:"flow"`
			Encryption string `json:"encryption"`
		} `json:"users"`
	}{
		Address: serverAddr,
		Port:    serverPort,
		Users: []struct {
			ID         string `json:"id"`
			Flow       string `json:"flow"`
			Encryption string `json:"encryption"`
		}{{
			ID:         userID,
			Flow:       flow,
			Encryption: encryption,
		}},
	})

	if protocol == "trojan" {
		outbound.Settings.Servers = append(outbound.Settings.Servers, struct {
			Address  string `json:"address"`
			Port     int    `json:"port"`
			Password string `json:"password"`
		}{
			Address:  serverAddr,
			Port:     serverPort,
			Password: userID,
		})
		outbound.Settings.VNext = nil
	}

	config.Outbounds = append(config.Outbounds, outbound)

	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
		return "", err
	}

	return tmpFile, nil
}

func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func checkTCPProxy(parsed *url.URL, timeoutSec float64) bool {
	host := parsed.Hostname()
	port := 443
	if parsed.Port() != "" {
		port, _ = strconv.Atoi(parsed.Port())
	}

	timeout := time.Duration(timeoutSec*1000) * time.Millisecond
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkHTTPProxy(parsed *url.URL, timeoutSec float64, testURL string) (bool, int) {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeoutSec*1000) * time.Millisecond,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec*1000) * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec*1000)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false, 0
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, resp.StatusCode
	}

	return false, resp.StatusCode
}
