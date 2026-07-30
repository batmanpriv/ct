package xp

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

	BatchSize int

	SkipUpdateCheck bool
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

const (
	defaultBatchSize      = 40
	xrayGithubOwnerRepo   = "XTLS/Xray-core"
	xrayVersionFileName   = "version.txt"
	socksReadyMaxAttempts = 60
	socksReadyDelay       = 150 * time.Millisecond
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
		fmt.Printf("%sDownloaded %d unique configs%s\n", colorGreen, len(configs), colorReset)
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

	xrayPath, err := ensureXrayBinary(!config.SkipUpdateCheck)
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
	if config.BatchSize <= 0 {
		config.BatchSize = defaultBatchSize
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
	fmt.Printf("%sConcurrent xray instances: %d | Batch size: %d | Timeout: %.1fs%s\n",
		colorCyan, config.Threads, config.BatchSize, config.Timeout, colorReset)
	fmt.Printf("\n%sTesting configs...%s\n\n", colorBold, colorReset)

	items := make([]batchItem, len(configs))
	for i, cfg := range configs {
		items[i] = prepareItem(i, cfg)
	}

	results := make([]TestResult, len(configs))
	printed := make([]bool, len(configs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)
	var mu sync.Mutex
	nextIndex := 0

	printResult := func(idx int, r TestResult) {
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
		if r.Alive {
			fmt.Printf("%s[%d] \u2713 ALIVE%s %s (%s) %.0fms%s%s%s\n",
				colorGreen, idx, colorReset, r.Server, r.Protocol, r.Latency.Seconds()*1000, statusInfo, ipInfo, loc)
		} else {
			fmt.Printf("%s[%d] \u2717 DEAD%s %s: %s\n", colorRed, idx, colorReset, r.Server, r.ErrorMsg)
		}
	}

	commitBatch := func(batchResults []TestResult) {
		mu.Lock()
		for _, r := range batchResults {
			results[r.Index] = r
		}
		for nextIndex < len(results) && results[nextIndex].Config != "" {
			r := results[nextIndex]
			if r.Alive {
				appendAliveConfig(outputFile, r.Config)
				if config.RegionSort && r.Country != "" {
					appendAliveConfig(getRegionFile(config.RegionDir, r.Country), r.Config)
				}
			}
			printResult(nextIndex, r)
			printed[nextIndex] = true
			nextIndex++
		}
		mu.Unlock()
	}

	for start := 0; start < len(items); start += config.BatchSize {
		end := start + config.BatchSize
		if end > len(items) {
			end = len(items)
		}
		batch := items[start:end]

		wg.Add(1)
		go func(batch []batchItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			batchResults := runBatch(xrayPath, batch, config.Timeout, config.TestURL)
			commitBatch(batchResults)
		}(batch)
	}

	wg.Wait()

	mu.Lock()
	for i := 0; i < len(results); i++ {
		if printed[i] {
			continue
		}
		printResult(i, results[i])
	}
	mu.Unlock()

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

func normalizeConfigKey(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
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

			client := &http.Client{Timeout: 15 * time.Second}
			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			resp, err := client.Do(req)
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

			text := string(body)
			if looksLikeBase64Blob(text) {
				if decoded, derr := decodeB64Flex(strings.TrimSpace(text)); derr == nil {
					text = string(decoded)
				}
			}

			scanner := bufio.NewScanner(strings.NewReader(text))
			scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if !isKnownScheme(line) {
					continue
				}
				key := normalizeConfigKey(line)
				mu.Lock()
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					allConfigs = append(allConfigs, line)
				}
				mu.Unlock()
			}
		}(source)
	}

	wg.Wait()
	return allConfigs, nil
}

func isKnownScheme(line string) bool {
	switch {
	case strings.HasPrefix(line, "vless://"),
		strings.HasPrefix(line, "vmess://"),
		strings.HasPrefix(line, "trojan://"),
		strings.HasPrefix(line, "ss://"):
		return true
	default:
		return false
	}
}

var base64BlobRe = regexp.MustCompile(`^[A-Za-z0-9+/_=\-\r\n]+$`)

func looksLikeBase64Blob(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 20 {
		return false
	}
	if strings.Contains(t, "://") {
		return false
	}
	return base64BlobRe.MatchString(t)
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
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key := normalizeConfigKey(line)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
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

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func ensureXrayBinary(checkUpdate bool) (string, error) {
	xrayDir, err := xrayInstallDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(xrayDir, 0755); err != nil {
		return "", err
	}

	binaryName := "xray"
	if runtime.GOOS == "windows" {
		binaryName = "xray.exe"
	}
	xrayPath := filepath.Join(xrayDir, binaryName)
	versionPath := filepath.Join(xrayDir, xrayVersionFileName)

	_, statErr := os.Stat(xrayPath)
	haveBinary := statErr == nil
	currentVersion := ""
	if haveBinary {
		if v, err := os.ReadFile(versionPath); err == nil {
			currentVersion = strings.TrimSpace(string(v))
		}
	}

	if !checkUpdate {
		if haveBinary {
			return xrayPath, nil
		}
		checkUpdate = true 
	}

	fmt.Printf("%sChecking for the latest Xray-core release...%s\n", colorCyan, colorReset)
	release, relErr := fetchLatestXrayRelease()
	if relErr != nil {
		if haveBinary {
			fmt.Printf("%sCould not check for updates (%v); using existing binary (%s)%s\n",
				colorYellow, relErr, orUnknown(currentVersion), colorReset)
			return xrayPath, nil
		}
		return "", fmt.Errorf("no local xray binary and update check failed: %v", relErr)
	}

	if haveBinary && currentVersion == release.TagName {
		fmt.Printf("%sXray-core is up to date (%s)%s\n", colorGreen, currentVersion, colorReset)
		return xrayPath, nil
	}

	if haveBinary {
		fmt.Printf("%sNewer Xray-core available: %s -> %s. Downloading...%s\n",
			colorYellow, orUnknown(currentVersion), release.TagName, colorReset)
	} else {
		fmt.Printf("%sDownloading Xray-core %s for %s/%s...%s\n",
			colorPurple, release.TagName, runtime.GOOS, runtime.GOARCH, colorReset)
	}

	assetName, assetURL, err := pickAssetForPlatform(release)
	if err != nil {
		if haveBinary {
			fmt.Printf("%s%v; keeping existing binary%s\n", colorYellow, err, colorReset)
			return xrayPath, nil
		}
		return "", err
	}

	if err := downloadAndInstall(assetName, assetURL, xrayDir, xrayPath, binaryName); err != nil {
		if haveBinary {
			fmt.Printf("%sDownload/install failed (%v); keeping existing binary%s\n", colorYellow, err, colorReset)
			return xrayPath, nil
		}
		return "", err
	}

	_ = os.WriteFile(versionPath, []byte(release.TagName), 0644)
	fmt.Printf("%sInstalled Xray-core %s%s\n", colorGreen, release.TagName, colorReset)
	return xrayPath, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func xrayInstallDir() (string, error) {
	if runtime.GOOS == "windows" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(homeDir, ".xray-test"), nil
	}
	return filepath.Join(os.TempDir(), ".xray-test"), nil
}

func fetchLatestXrayRelease() (*githubRelease, error) {
	client := &http.Client{Timeout: 12 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+xrayGithubOwnerRepo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "xray-checker")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github api returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("unexpected github api response")
	}
	return &rel, nil
}

func platformAssetName() (string, error) {
	osName := runtime.GOOS
	switch osName {
	case "darwin":
		osName = "macos"
	case "linux", "windows", "freebsd":
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "64"
	case "386":
		arch = "32"
	case "arm64":
		arch = "arm64-v8a"
	case "arm":
		arch = "arm32-v7a"
	case "mips64":
		arch = "mips64"
	case "mips64le":
		arch = "mips64le"
	case "mips":
		arch = "mips32"
	case "mipsle":
		arch = "mips32le"
	case "riscv64":
		arch = "riscv64"
	case "s390x":
		arch = "s390x"
	default:
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	return fmt.Sprintf("Xray-%s-%s.zip", osName, arch), nil
}

func pickAssetForPlatform(release *githubRelease) (assetName string, downloadURL string, err error) {
	wantName, err := platformAssetName()
	if err != nil {
		return "", "", err
	}
	for _, a := range release.Assets {
		if a.Name == wantName {
			return a.Name, a.BrowserDownloadURL, nil
		}
	}

	return wantName, fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", xrayGithubOwnerRepo, wantName), nil
}

func downloadAndInstall(assetName, assetURL, xrayDir, xrayPath, binaryName string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	body, err := fetchBytes(client, assetURL)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}

	if dgst, derr := fetchBytes(client, assetURL+".dgst"); derr == nil {
		if !verifySHA256Digest(body, dgst) {
			return fmt.Errorf("checksum mismatch for %s", assetName)
		}
	} else {
		fmt.Printf("%sNote: could not verify checksum for %s (%v)%s\n", colorYellow, assetName, derr, colorReset)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}

	tmpPath := xrayPath + ".new"
	found := false
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if base == binaryName {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return err
			}
			_, cErr := io.Copy(out, rc)
			rc.Close()
			out.Close()
			if cErr != nil {
				return cErr
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("binary %q not found in %s", binaryName, assetName)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0755); err != nil {
			return err
		}
	}
	return os.Rename(tmpPath, xrayPath)
}

func fetchBytes(client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xray-checker")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func verifySHA256Digest(data []byte, dgstFile []byte) bool {
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])

	hexTokenRe := regexp.MustCompile(`[a-fA-F0-9]{64}`)
	matches := hexTokenRe.FindAllString(string(dgstFile), -1)
	if len(matches) == 0 {
		return true 
	}
	for _, m := range matches {
		if strings.EqualFold(m, want) {
			return true
		}
	}
	return false
}

type batchItem struct {
	Index    int
	Config   string
	Protocol string
	Server   string
	Outbound map[string]any
	ParseErr error
}

type portItem struct {
	item batchItem
	port int
}

func prepareItem(index int, config string) batchItem {
	item := batchItem{
		Index:    index,
		Config:   config,
		Protocol: detectProtocol(config),
		Server:   "unknown",
	}
	if server := extractServer(config); server != "" {
		item.Server = server
	}
	outbound, err := buildOutbound(config)
	if err != nil {
		item.ParseErr = err
		return item
	}
	item.Outbound = outbound
	return item
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

func decodeB64Flex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	variants := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range variants {
		if data, err := enc.DecodeString(s); err == nil {
			return data, nil
		} else {
			lastErr = err
		}
	}
	
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if data, err := enc.DecodeString(trimmed); err == nil {
			return data, nil
		}
	}
	return nil, lastErr
}

func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
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

func extractServer(config string) string {
	switch {
	case strings.HasPrefix(config, "vmess://"):
		decoded, err := decodeB64Flex(strings.TrimPrefix(config, "vmess://"))
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
	decoded, err := decodeB64Flex(s)
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

func buildOutbound(link string) (map[string]any, error) {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		return buildVMessOutbound(link)
	case strings.HasPrefix(link, "ss://"):
		return buildSSOutbound(link)
	case strings.HasPrefix(link, "vless://"), strings.HasPrefix(link, "trojan://"):
		return buildURLOutbound(link)
	default:
		return nil, fmt.Errorf("unsupported or unrecognized config scheme")
	}
}

func buildVMessOutbound(link string) (map[string]any, error) {
	encoded := strings.TrimPrefix(link, "vmess://")
	decoded, err := decodeB64Flex(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vmess: %v", err)
	}

	var v VMessConfig
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("failed to parse vmess json: %v", err)
	}
	if v.Add == "" {
		return nil, fmt.Errorf("vmess config missing server address")
	}
	if !isValidUUID(v.ID) {
		return nil, fmt.Errorf("invalid UUID in vmess config")
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
		sni = v.Host
	}
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
		h2 := map[string]any{"path": path}
		if v.Host != "" {
			h2["host"] = []string{v.Host}
		}
		stream["httpSettings"] = h2
	case "httpupgrade":
		hu := map[string]any{"path": path}
		if v.Host != "" {
			hu["host"] = v.Host
		}
		stream["httpupgradeSettings"] = hu
	case "splithttp", "xhttp":
		stream["network"] = "splithttp"
		sh := map[string]any{"path": path}
		if v.Host != "" {
			sh["host"] = v.Host
		}
		stream["splithttpSettings"] = sh
	case "quic":
		stream["quicSettings"] = map[string]any{"security": "none"}
	case "kcp":
		stream["kcpSettings"] = map[string]any{"header": map[string]any{"type": nonEmpty(v.Type, "none")}}
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

	return proxyOutbound, nil
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func buildURLOutbound(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("failed to parse link: %v", err)
	}

	protocol := u.Scheme
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
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

	if protocol != "trojan" && !isValidUUID(userID) {
		return nil, fmt.Errorf("invalid UUID: %s", userID)
	}
	if protocol == "trojan" && userID == "" {
		return nil, fmt.Errorf("trojan config missing password")
	}

	q := u.Query()
	security := q.Get("security")
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
	if sni == "" {
		sni = hostHeader
	}
	if sni == "" {
		sni = host
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
	if serviceName == "" {
		serviceName = path
	}
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
	allowInsecure := q.Get("allowInsecure") == "true" || q.Get("allowInsecure") == "1"

	if security == "" {
		if pbk != "" || sid != "" {
			security = "reality"
		} else {
			security = "none"
		}
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
	case "trojan":
		proxyOutbound["settings"] = map[string]any{
			"servers": []map[string]any{
				{"address": host, "port": serverPort, "password": userID},
			},
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
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
		h2 := map[string]any{"path": path}
		if hostHeader != "" {
			h2["host"] = []string{hostHeader}
		}
		stream["httpSettings"] = h2
	case "httpupgrade":
		hs := map[string]any{"path": path}
		if hostHeader != "" {
			hs["host"] = hostHeader
		}
		stream["httpupgradeSettings"] = hs
	case "splithttp", "xhttp":
		stream["network"] = "splithttp"
		hs := map[string]any{"path": path}
		if hostHeader != "" {
			hs["host"] = hostHeader
		}
		stream["splithttpSettings"] = hs
	case "quic":
		quicSecurity := q.Get("quicSecurity")
		if quicSecurity == "" {
			quicSecurity = "none"
		}
		qs := map[string]any{"security": quicSecurity}
		if key := q.Get("key"); key != "" {
			qs["key"] = key
		}
		if headerType != "" {
			qs["header"] = map[string]any{"type": headerType}
		}
		stream["quicSettings"] = qs
	case "kcp":
		stream["kcpSettings"] = map[string]any{"header": map[string]any{"type": nonEmpty(headerType, "none")}}
	case "tcp":
		if headerType != "" && headerType != "none" {
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": headerType}}
		}
	}

	switch security {
	case "tls":
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
	case "reality":
		if pbk == "" {
			return nil, fmt.Errorf("reality config missing public key")
		}
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

	return proxyOutbound, nil
}

func buildSSOutbound(link string) (map[string]any, error) {
	if plugin := ssPluginName(link); plugin != "" {
		return nil, fmt.Errorf("shadowsocks plugin %q is not supported by this checker", plugin)
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
			return nil, fmt.Errorf("invalid ss format: %v", err)
		}
		method, password, hostPart = dec[0], dec[1], dec[2]
	}

	if method == "" || hostPart == "" {
		return nil, fmt.Errorf("invalid ss format")
	}

	host, serverPort := parseSSHostPort(hostPart)
	if host == "" {
		return nil, fmt.Errorf("ss config missing server address")
	}
	if serverPort <= 0 {
		serverPort = 443
	}

	return map[string]any{
		"protocol": "shadowsocks",
		"tag":      "proxy",
		"settings": map[string]any{
			"servers": []map[string]any{
				{"address": host, "port": serverPort, "method": method, "password": password},
			},
		},
		"streamSettings": map[string]any{"network": "tcp", "security": "none"},
	}, nil
}

func ssPluginName(link string) string {
	q := strings.Index(link, "?")
	frag := strings.Index(link, "#")
	if q < 0 {
		return ""
	}
	end := len(link)
	if frag > q {
		end = frag
	}
	query := link[q+1 : end]
	values, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	plugin := values.Get("plugin")
	if plugin == "" {
		return ""
	}
	return strings.SplitN(plugin, ";", 2)[0]
}

func decodeSSAuth(s string) ([3]string, error) {
	var out [3]string
	dec, err := decodeB64Flex(s)
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

func runBatch(xrayPath string, batch []batchItem, timeoutSec float64, testURL string) []TestResult {
	results := make([]TestResult, len(batch))

	var ports []portItem

	for i, it := range batch {
		if it.ParseErr != nil {
			results[i] = TestResult{
				Index:    it.Index,
				Config:   it.Config,
				Protocol: it.Protocol,
				Server:   it.Server,
				ErrorMsg: it.ParseErr.Error(),
			}
			continue
		}
		port, err := getFreePort()
		if err != nil {
			results[i] = TestResult{
				Index:    it.Index,
				Config:   it.Config,
				Protocol: it.Protocol,
				Server:   it.Server,
				ErrorMsg: fmt.Sprintf("failed to allocate local port: %v", err),
			}
			continue
		}
		ports = append(ports, portItem{item: it, port: port})
	}

	if len(ports) == 0 {
		return results
	}

	inbounds := make([]map[string]any, 0, len(ports))
	outbounds := make([]map[string]any, 0, len(ports)+1)
	rules := make([]map[string]any, 0, len(ports))
	portToLocalIdx := make(map[int]int, len(ports))

	for localIdx, p := range ports {
		inTag := fmt.Sprintf("in-%d", localIdx)
		outTag := fmt.Sprintf("out-%d", localIdx)
		inbounds = append(inbounds, map[string]any{
			"tag":      inTag,
			"port":     p.port,
			"listen":   "127.0.0.1",
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true},
		})
		outbound := cloneMap(p.item.Outbound)
		outbound["tag"] = outTag
		outbounds = append(outbounds, outbound)
		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []string{inTag},
			"outboundTag": outTag,
		})
		portToLocalIdx[p.port] = localIdx
	}
	outbounds = append(outbounds, map[string]any{"protocol": "freedom", "tag": "direct"})

	fullConfig := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"dns":       map[string]any{"servers": []string{"1.1.1.1", "8.8.8.8"}},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}

	data, err := json.MarshalIndent(fullConfig, "", "  ")
	if err != nil {
		return fillBatchError(results, batch, ports, fmt.Sprintf("failed to build batch config: %v", err))
	}
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("xray_batch_%d_%d.json", time.Now().UnixNano(), os.Getpid()))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fillBatchError(results, batch, ports, fmt.Sprintf("failed to write batch config: %v", err))
	}
	defer os.Remove(tmpFile)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec*1000)*time.Millisecond+30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, xrayPath, "run", "-c", tmpFile)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return fillBatchError(results, batch, ports, fmt.Sprintf("failed to start xray: %v", err))
	}
	defer killProcess(cmd)

	readyPorts := waitForPortsReady(ports, socksReadyMaxAttempts, socksReadyDelay)

	targets := aliveTargets
	if testURL != "" {
		targets = []string{testURL}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	resultByLocalIdx := make(map[int]TestResult, len(ports))

	for _, p := range ports {
		localIdx := portToLocalIdx[p.port]
		wg.Add(1)
		go func(p portItem, localIdx int) {
			defer wg.Done()
			r := TestResult{
				Index:    p.item.Index,
				Config:   p.item.Config,
				Protocol: p.item.Protocol,
				Server:   p.item.Server,
			}
			if !readyPorts[p.port] {
				r.ErrorMsg = "socks5 not ready"
				mu.Lock()
				resultByLocalIdx[localIdx] = r
				mu.Unlock()
				return
			}

			ok, statusCode := checkHTTPProxy(p.port, timeoutSec, targets)
			if ok {
				r.Alive = true
				r.Latency = time.Since(start)
				r.StatusCode = statusCode
				if ip, ipStatus, ipOK := probePublicIP(p.port, timeoutSec); ipOK {
					r.PublicIP = ip
					if r.StatusCode == 0 {
						r.StatusCode = ipStatus
					}
				}
				if r.Server != "" && r.Server != "unknown" {
					geo := getGeoLocation(r.Server)
					r.Country = geo.Country
					r.City = geo.City
					r.ISP = geo.ISP
				}
			} else {
				r.ErrorMsg = "proxy check failed"
				if statusCode > 0 {
					r.StatusCode = statusCode
				}
			}
			mu.Lock()
			resultByLocalIdx[localIdx] = r
			mu.Unlock()
		}(p, localIdx)
	}
	wg.Wait()

	sharedErr := parseErr(stderr.String())

	batchLocalIdx := 0
	for i, it := range batch {
		if it.ParseErr != nil {
			continue 
		}
		if r, ok := resultByLocalIdx[batchLocalIdx]; ok {
			if !r.Alive && r.ErrorMsg == "socks5 not ready" && sharedErr != "" {
				r.ErrorMsg = sharedErr
			}
			results[i] = r
		}
		batchLocalIdx++
	}

	return results
}

func fillBatchError(results []TestResult, batch []batchItem, ports []portItem, msg string) []TestResult {
	for _, p := range ports {
		for i, it := range batch {
			if it.Index == p.item.Index {
				results[i] = TestResult{
					Index:    it.Index,
					Config:   it.Config,
					Protocol: it.Protocol,
					Server:   it.Server,
					ErrorMsg: msg,
				}
			}
		}
	}
	return results
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func waitForPortsReady(ports []portItem, maxAttempts int, delay time.Duration) map[int]bool {
	ready := make(map[int]bool, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			for i := 0; i < maxAttempts; i++ {
				if checkSOCKS5Ready(port) {
					mu.Lock()
					ready[port] = true
					mu.Unlock()
					return
				}
				time.Sleep(delay)
			}
		}(p.port)
	}
	wg.Wait()
	return ready
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

func killProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func parseErr(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		l := strings.ToLower(line)
		if strings.Contains(l, "error") || strings.Contains(l, "failed") || strings.Contains(l, "refused") ||
			strings.Contains(l, "timeout") || strings.Contains(l, "dial") || strings.Contains(l, "uuid") {
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
		ResponseHeaderTimeout: timeout,
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
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       5 * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	type res struct {
		ip   string
		code int
		ok   bool
	}
	ch := make(chan res, len(publicIPChecks))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, endpoint := range publicIPChecks {
		go func(endpoint string) {
			reqCtx, reqCancel := context.WithTimeout(ctx, timeout)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
			if err != nil {
				ch <- res{}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			resp, err := client.Do(req)
			if err != nil {
				ch <- res{}
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				ch <- res{}
				return
			}
			s := strings.TrimSpace(string(body))
			if s == "" {
				ch <- res{}
				return
			}
			if strings.HasPrefix(s, "{") {
				var m map[string]any
				if json.Unmarshal(body, &m) == nil {
					if ip, ok := m["ip"].(string); ok && ip != "" {
						ch <- res{ip: ip, code: resp.StatusCode, ok: true}
						return
					}
					if ip, ok := m["origin"].(string); ok && ip != "" {
						ch <- res{ip: ip, code: resp.StatusCode, ok: true}
						return
					}
				}
				ch <- res{}
				return
			}
			ch <- res{ip: s, code: resp.StatusCode, ok: true}
		}(endpoint)
	}

	for range publicIPChecks {
		r := <-ch
		if r.ok {
			cancel()
			return r.ip, r.code, true
		}
	}
	return "", 0, false
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
