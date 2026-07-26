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
	ConfigFile  string
	Download    bool
	Limit       int
	Threads     int
	Timeout     float64
	AddSource   string
	TestURL     string
	NoColor     bool
	OutputFile  string
	RegionSort  bool
	RegionDir   string
}

type VMessConfig struct {
	V          string `json:"v"`
	Ps         string `json:"ps"`
	Add        string `json:"add"`
	Port       string `json:"port"`
	ID         string `json:"id"`
	Aid        string `json:"aid"`
	Net        string `json:"net"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	TLS        string `json:"tls"`
	Sni        string `json:"sni"`
	Alpn       string `json:"alpn"`
	Fingerprint string `json:"fp"`
	Security   string `json:"security"`
}

type SSConfig struct {
	Method   string
	Password string
	Server   string
	Port     int
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
		config.Threads = 3
	}
	if config.Timeout == 0 {
		config.Timeout = 10.0
	}
	fmt.Printf("%sThreads: %d, Timeout: %.1fs%s\n", colorCyan, config.Threads, config.Timeout, colorReset)

	outputFile := config.OutputFile
	if outputFile == "" {
		outputFile = "alive_configs.txt"
	}

	if config.RegionSort {
		if config.RegionDir == "" {
			config.RegionDir = "regions"
		}
		os.MkdirAll(config.RegionDir, 0755)
		fmt.Printf("%sRegion sorting enabled, output dir: %s%s\n", colorPurple, config.RegionDir, colorReset)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("%sError creating alive file: %v%s\n", colorRed, err, colorReset)
		return
	}
	f.Close()

	results := make([]TestResult, len(configs))
	printed := make([]bool, len(configs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)
	var mu sync.Mutex
	nextIndex := 0

	fmt.Printf("\n%sTesting configs...%s\n\n", colorBold, colorReset)

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
				result = results[nextIndex]
				if result.Alive {
					appendAliveConfig(outputFile, result.Config)
					if config.RegionSort && result.Country != "" {
						regionFile := getRegionFile(config.RegionDir, result.Country)
						appendAliveConfig(regionFile, result.Config)
					}

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
						colorGreen, nextIndex, colorGreen, colorReset,
						result.Server, result.Protocol, result.Latency.Seconds()*1000,
						statusInfo, colorWhite, location)
				} else {
					fmt.Printf("%s[%d] %s✗ DEAD%s %s: %s%s\n",
						colorRed, nextIndex, colorRed, colorReset,
						result.Server, result.ErrorMsg, colorReset)
				}
				printed[nextIndex] = true
				nextIndex++
			}
			mu.Unlock()
		}(i, cfg)
	}

	wg.Wait()

	for i := nextIndex; i < len(results); i++ {
		if !printed[i] {
			result := results[i]
			if result.Alive {
				fmt.Printf("%s[%d] %s✓ ALIVE%s %s(%s) %.0fms%s%s%s\n",
					colorGreen, i, colorGreen, colorReset,
					result.Server, result.Protocol, result.Latency.Seconds()*1000,
					"", colorWhite, "")
			} else {
				fmt.Printf("%s[%d] %s✗ DEAD%s %s: %s%s\n",
					colorRed, i, colorRed, colorReset,
					result.Server, result.ErrorMsg, colorReset)
			}
		}
	}

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

		if config.RegionSort {
			fmt.Printf("\n%sRegion files saved in: %s/%s\n", colorGreen, config.RegionDir, colorReset)
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
	filename := strings.ReplaceAll(country, " ", "_")
	filename = strings.ReplaceAll(filename, "-", "_")
	filename = strings.ToLower(filename)
	return filepath.Join(regionDir, filename+".txt")
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

	var binaryName string
	if runtime.GOOS == "windows" {
		binaryName = "xray.exe"
	} else {
		binaryName = "xray"
	}

	xrayPath := filepath.Join(xrayDir, binaryName)

	if _, err := os.Stat(xrayPath); err == nil {
		return xrayPath, nil
	}

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

	server := extractServer(config)
	if server != "" {
		result.Server = server
		geo := getGeoLocation(server)
		result.Country = geo.Country
		result.City = geo.City
		result.ISP = geo.ISP
	} else {
		result.Server = "unknown"
	}

	if strings.HasPrefix(config, "vless://") {
		result.Protocol = "vless"
	} else if strings.HasPrefix(config, "vmess://") {
		result.Protocol = "vmess"
	} else if strings.HasPrefix(config, "trojan://") {
		result.Protocol = "trojan"
	} else if strings.HasPrefix(config, "ss://") {
		result.Protocol = "ss"
	} else {
		result.Protocol = "unknown"
	}

	cfgFile, port, err := createXrayConfigFromLink(config)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("config error: %v", err)
		return result
	}
	defer os.Remove(cfgFile)

	timeoutDuration := time.Duration(timeoutSec*1000) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration+15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, xrayPath, "run", "-c", cfgFile)

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err = cmd.Start()
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("start error: %v", err)
		return result
	}

	if !waitForSOCKS5Ready(port, 30, 200*time.Millisecond) {
		result.ErrorMsg = "Error"
		cmd.Process.Kill()
		cmd.Wait()
		return result
	}

	alive := false
	testURLs := []string{
		"https://www.gstatic.com/generate_204",
		"https://cp.cloudflare.com/generate_204",
		"https://clients3.google.com/generate_204",
		"https://1.1.1.1/cdn-cgi/trace",
	}

	if testURL != "" {
		testURLs = []string{testURL}
	}

	for _, url := range testURLs {
		alive, result.StatusCode = checkHTTPProxy(port, timeoutSec, url)
		if alive {
			break
		}
	}

	if alive {
		result.Alive = true
		result.Latency = time.Since(start)
	} else {
		if stderr.Len() > 0 {
			errOutput := stderr.String()
			errLines := strings.Split(errOutput, "\n")
			for _, line := range errLines {
				if strings.Contains(line, "rejected") || strings.Contains(line, "failed") ||
					strings.Contains(line, "error") || strings.Contains(line, "timeout") ||
					strings.Contains(line, "Refused") || strings.Contains(line, "refused") ||
					strings.Contains(line, "dial") || strings.Contains(line, "connection") ||
					strings.Contains(line, "UUID") {
					result.ErrorMsg = strings.TrimSpace(line)
					break
				}
			}
			if result.ErrorMsg == "" && len(errLines) > 0 {
				for i := len(errLines) - 1; i >= 0; i-- {
					if strings.TrimSpace(errLines[i]) != "" {
						result.ErrorMsg = strings.TrimSpace(errLines[i])
						break
					}
				}
			}
			if result.ErrorMsg == "" {
				result.ErrorMsg = "connection failed"
			}
		} else {
			result.ErrorMsg = "not responding or proxy refused connection"
		}
	}

	cmd.Process.Kill()
	cmd.Wait()

	return result
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

func extractServer(config string) string {
	if strings.HasPrefix(config, "vmess://") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(config, "vmess://"))
		if err == nil {
			var vconf VMessConfig
			if err := json.Unmarshal(decoded, &vconf); err == nil {
				return vconf.Add
			}
		}
		return ""
	}

	if strings.HasPrefix(config, "ss://") {
		parts := strings.SplitN(strings.TrimPrefix(config, "ss://"), "@", 2)
		if len(parts) == 2 {
			hostPart := parts[1]
			if strings.Contains(hostPart, ":") {
				host, _, err := net.SplitHostPort(hostPart)
				if err == nil {
					return host
				}
				colonIdx := strings.LastIndex(hostPart, ":")
				if colonIdx > 0 {
					return hostPart[:colonIdx]
				}
			}
			return hostPart
		}
		return ""
	}

	if strings.Contains(config, "://") {
		parts := strings.SplitN(config, "://", 2)
		if len(parts) == 2 {
			rest := parts[1]
			atIndex := strings.Index(rest, "@")
			if atIndex != -1 {
				hostPart := rest[atIndex+1:]
				questionIndex := strings.Index(hostPart, "?")
				if questionIndex != -1 {
					hostPart = hostPart[:questionIndex]
				}
				hashIndex := strings.Index(hostPart, "#")
				if hashIndex != -1 {
					hostPart = hostPart[:hashIndex]
				}
				if strings.Contains(hostPart, ":") {
					host, _, err := net.SplitHostPort(hostPart)
					if err == nil {
						return host
					}
					colonIdx := strings.LastIndex(hostPart, ":")
					if colonIdx > 0 {
						hostPart = hostPart[:colonIdx]
					}
				}
				return hostPart
			}
		}
	}
	return ""
}

func isValidUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		return false
	}
	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return false
	}
	for _, p := range parts {
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
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

	parsed, err := url.Parse(link)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse link: %v", err)
	}

	protocol := parsed.Scheme
	userInfo := parsed.User
	var userID string
	var password string
	if userInfo != nil {
		userID = userInfo.Username()
		password, _ = userInfo.Password()
	}
	if userID == "" && password != "" {
		userID = password
	}

	if !isValidUUID(userID) && protocol != "trojan" {
		return "", 0, fmt.Errorf("invalid UUID: %s", userID)
	}

	host := parsed.Hostname()
	portStr := parsed.Port()
	serverPort := 443
	if portStr != "" {
		serverPort, _ = strconv.Atoi(portStr)
	}

	query := parsed.Query()
	security := query.Get("security")
	if security == "" {
		security = "none"
	}
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
	if sni == "" {
		sni = query.Get("serverName")
	}
	pbk := query.Get("pbk")
	if pbk == "" {
		pbk = query.Get("publicKey")
	}
	sid := query.Get("sid")
	if sid == "" {
		sid = query.Get("shortId")
	}
	serviceName := query.Get("serviceName")
	flow := query.Get("flow")
	encryption := query.Get("encryption")
	if encryption == "" {
		encryption = "none"
	}
	fingerprint := query.Get("fp")
	if fingerprint == "" {
		fingerprint = query.Get("fingerprint")
	}
	alpn := query.Get("alpn")
	headerType := query.Get("headerType")
	allowInsecure := query.Get("allowInsecure") == "true"

	outbound := map[string]interface{}{
		"protocol": protocol,
		"tag":      "proxy",
		"settings": map[string]interface{}{},
		"streamSettings": map[string]interface{}{
			"network":  network,
			"security": security,
		},
	}

	if protocol == "vless" {
		users := []map[string]interface{}{
			{
				"id":         userID,
				"encryption": encryption,
			},
		}
		if flow != "" {
			users[0]["flow"] = flow
		}
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": host,
					"port":    serverPort,
					"users":   users,
				},
			},
		}
	} else if protocol == "vmess" {
		users := []map[string]interface{}{
			{
				"id": userID,
			},
		}
		if encryption != "" {
			users[0]["encryption"] = encryption
		}
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": host,
					"port":    serverPort,
					"users":   users,
				},
			},
		}
	} else if protocol == "trojan" {
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  host,
					"port":     serverPort,
					"password": userID,
				},
			},
		}
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})

	switch network {
	case "ws":
		wsSettings := map[string]interface{}{
			"path": path,
		}
		if hostHeader != "" {
			wsSettings["headers"] = map[string]string{"Host": hostHeader}
		}
		streamSettings["wsSettings"] = wsSettings
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": serviceName,
		}
	case "tcp":
		if headerType != "" && headerType != "none" {
			streamSettings["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": headerType,
				},
			}
		}
	case "xhttp":
		xhttpSettings := map[string]interface{}{
			"path": path,
		}
		if hostHeader != "" {
			xhttpSettings["host"] = hostHeader
		}
		streamSettings["xhttpSettings"] = xhttpSettings
	case "httpupgrade":
		httpupgradeSettings := map[string]interface{}{
			"path": path,
		}
		if hostHeader != "" {
			httpupgradeSettings["host"] = hostHeader
		}
		streamSettings["httpupgradeSettings"] = httpupgradeSettings
	}

	if security == "tls" {
		tlsSettings := map[string]interface{}{
			"serverName": sni,
		}
		if fingerprint != "" {
			tlsSettings["fingerprint"] = fingerprint
		}
		if alpn != "" {
			alpnParts := strings.Split(alpn, ",")
			for i, p := range alpnParts {
				alpnParts[i] = strings.TrimSpace(p)
			}
			tlsSettings["alpn"] = alpnParts
		}
		if allowInsecure {
			tlsSettings["allowInsecure"] = true
		}
		streamSettings["tlsSettings"] = tlsSettings
	} else if security == "reality" {
		realitySettings := map[string]interface{}{
			"serverName": sni,
			"publicKey":  pbk,
			"shortId":    sid,
		}
		if fingerprint != "" {
			realitySettings["fingerprint"] = fingerprint		}
		if alpn != "" {
			alpnParts := strings.Split(alpn, ",")
			for i, p := range alpnParts {
				alpnParts[i] = strings.TrimSpace(p)
			}
			realitySettings["alpn"] = alpnParts
		}
		streamSettings["realitySettings"] = realitySettings
	}

	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"port":     port,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "none",
				},
			},
		},
		"outbounds": []map[string]interface{}{
			outbound,
		},
	}

	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", 0, err
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%d_%d.json", time.Now().UnixNano(), os.Getpid()))
	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
		return "", 0, err
	}

	return tmpFile, port, nil
}

func createVMessConfig(link string) (string, int, error) {
	port, err := getFreePort()
	if err != nil {
		return "", 0, err
	}

	encoded := strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode vmess: %v", err)
	}

	var vconf VMessConfig
	if err := json.Unmarshal(decoded, &vconf); err != nil {
		return "", 0, fmt.Errorf("failed to parse vmess json: %v", err)
	}

	if !isValidUUID(vconf.ID) {
		return "", 0, fmt.Errorf("invalid UUID in vmess config")
	}

	serverPort, _ := strconv.Atoi(vconf.Port)
	if serverPort == 0 {
		serverPort = 443
	}

	security := vconf.TLS
	if security == "" {
		security = "none"
	}
	if security == "tls" || security == "xtls" {
		security = "tls"
	}

	network := vconf.Net
	if network == "" {
		network = "tcp"
	}

	path := vconf.Path
	if path == "" {
		path = "/"
	}

	hostHeader := vconf.Host
	sni := vconf.Sni
	if sni == "" {
		sni = vconf.Host
	}

	fingerprint := vconf.Fingerprint
	alpn := vconf.Alpn

	outbound := map[string]interface{}{
		"protocol": "vmess",
		"tag":      "proxy",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": vconf.Add,
					"port":    serverPort,
					"users": []map[string]interface{}{
						{
							"id":   vconf.ID,
							"security": vconf.Security,
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  network,
			"security": security,
		},
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})

	switch network {
	case "ws":
		wsSettings := map[string]interface{}{
			"path": path,
		}
		if hostHeader != "" {
			wsSettings["headers"] = map[string]string{"Host": hostHeader}
		}
		streamSettings["wsSettings"] = wsSettings
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": path,
		}
	case "tcp":
		if vconf.Type != "" && vconf.Type != "none" && vconf.Type != "http" {
			streamSettings["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": vconf.Type,
				},
			}
		}
	case "http":
		streamSettings["httpSettings"] = map[string]interface{}{
			"path": path,
		}
	}

	if security == "tls" {
		tlsSettings := map[string]interface{}{
			"serverName": sni,
		}
		if fingerprint != "" {
			tlsSettings["fingerprint"] = fingerprint
		}
		if alpn != "" {
			alpnParts := strings.Split(alpn, ",")
			for i, p := range alpnParts {
				alpnParts[i] = strings.TrimSpace(p)
			}
			tlsSettings["alpn"] = alpnParts
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"port":     port,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "none",
				},
			},
		},
		"outbounds": []map[string]interface{}{
			outbound,
		},
	}

	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", 0, err
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%d_%d.json", time.Now().UnixNano(), os.Getpid()))
	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
		return "", 0, err
	}

	return tmpFile, port, nil
}

func createSSConfig(link string) (string, int, error) {
	port, err := getFreePort()
	if err != nil {
		return "", 0, err
	}

	ssLink := strings.TrimPrefix(link, "ss://")
	parts := strings.SplitN(ssLink, "@", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid ss format")
	}

	authPart := parts[0]
	hostPart := parts[1]

	hostPart = strings.Split(hostPart, "#")[0]
	hostPart = strings.Split(hostPart, "?")[0]

	var host string
	var serverPort int

	if strings.HasPrefix(hostPart, "[") {
		bracketEnd := strings.Index(hostPart, "]")
		if bracketEnd == -1 {
			return "", 0, fmt.Errorf("invalid IPv6 format")
		}
		host = hostPart[1:bracketEnd]
		portStr := hostPart[bracketEnd+1:]
		if strings.HasPrefix(portStr, ":") {
			serverPort, _ = strconv.Atoi(portStr[1:])
		}
	} else {
		hostParts := strings.Split(hostPart, ":")
		if len(hostParts) >= 2 {
			host = strings.Join(hostParts[:len(hostParts)-1], ":")
			serverPort, _ = strconv.Atoi(hostParts[len(hostParts)-1])
		}
	}

	if serverPort == 0 {
		serverPort = 443
	}

	var method, password string
	if strings.Contains(authPart, ":") && !strings.Contains(authPart, "=") {
		decoded, err := base64.StdEncoding.DecodeString(authPart)
		if err == nil {
			authStr := string(decoded)
			authParts := strings.SplitN(authStr, ":", 2)
			if len(authParts) == 2 {
				method = authParts[0]
				password = authParts[1]
			}
		}
	}

	if method == "" {
		parts = strings.SplitN(authPart, ":", 2)
		if len(parts) == 2 {
			method = parts[0]
			password = parts[1]
		}
	}

	if method == "" {
		return "", 0, fmt.Errorf("could not parse ss auth")
	}

	outbound := map[string]interface{}{
		"protocol": "shadowsocks",
		"tag":      "proxy",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  host,
					"port":     serverPort,
					"method":   method,
					"password": password,
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "tcp",
			"security": "none",
		},
	}

	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"port":     port,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "none",
				},
			},
		},
		"outbounds": []map[string]interface{}{
			outbound,
		},
	}

	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", 0, err
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("xray_test_%d_%d.json", time.Now().UnixNano(), os.Getpid()))
	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
		return "", 0, err
	}

	return tmpFile, port, nil
}

func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func checkSOCKS5Ready(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkHTTPProxy(port int, timeoutSec float64, testURL string) (bool, int) {
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
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

	if resp.StatusCode == 200 {
		return true, resp.StatusCode
	}

	return false, resp.StatusCode
}
