package scraper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Reset     = "\033[0m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Magenta   = "\033[35m"
	Cyan      = "\033[36m"
	Gray      = "\033[37m"
	White     = "\033[97m"
	Bold      = "\033[1m"
	BrightRed = "\033[91m"
)

type SourceConfig struct {
	URLs  []string `json:"urls"`
	PType string   `json:"type,omitempty"`
}

type Config struct {
	Configs      []string            `json:"configs"`
	MTProto      []string            `json:"mtproto"`
	Proxies      map[string][]string `json:"proxies"`
	Telegram     []string            `json:"telegram"`
	Custom       []SourceConfig      `json:"custom,omitempty"`
	LastRun      string              `json:"last_run"`
	SkipTelegram bool                `json:"skip_telegram"`
}

type ScrapeResult struct {
	Items      []string
	SourceType string
	Error      error
}

type Job struct {
	url        string
	name       string
	kind       string
	sourceType string
}

type Scraper struct {
	Config       *Config
	OutputDir    string
	Workers      int
	SkipTelegram bool
	mu           sync.Mutex
}

var (
	defaultConfigsURLs = []string{
		"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
		"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt",
		"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/raw/refs/heads/main/trojan_configs.txt",
		"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/raw/refs/heads/main/ss_configs.txt",
		"https://raw.githubusercontent.com/Epodonios/v2ray-configs/raw/refs/heads/main/Sub1.txt",
		"https://raw.githubusercontent.com/roosterkid/openproxylist/raw/refs/heads/main/V2RAY_RAW.txt",
		"https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/vless.txt",
		"https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/shadowsocks.txt",
		"https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/raw/refs/heads/main/sub.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub5.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub6.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub7.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub8.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/refs/heads/main/All_Configs_Sub.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
		"https://github.com/MustafaBaqer/VestraNet-Nodes/raw/refs/heads/main/protocols/vmess.txt",
		"https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/all_servers.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
		"https://github.com/lm705/vair/raw/refs/heads/main/vless_alive.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
		"https://github.com/MustafaBaqer/VestraNet-Nodes/blob/main/protocols/trojan.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
		"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ssr.txt",
	}

	defaultMTProtoURLs = []string{
		"https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
		"https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
		"https://github.com/MustafaBaqer/VestraNet-Nodes/blob/main/protocols/mtproto.txt",
	}

	defaultProxyURLs = map[string][]string{
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

	defaultTelegramChannels = []string{
		"https://t.me/ProxyMTProto",
		"https://t.me/NPROXY",
		"https://t.me/PinkProxy",
		"https://t.me/jackalproxy",
		"https://t.me/Myporoxy",
		"https://t.me/MTProtoProxies",
		"https://t.me/iRoProxy",
	}

	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
	}

	vlessRegex   = regexp.MustCompile(`vless://[^\s"'<>]+`)
	vmessRegex   = regexp.MustCompile(`vmess://[^\s"'<>]+`)
	trojanRegex  = regexp.MustCompile(`trojan://[^\s"'<>]+`)
	ssRegex      = regexp.MustCompile(`ss://[^\s"'<>]+`)
	ssrRegex     = regexp.MustCompile(`ssr://[^\s"'<>]+`)
	mtprotoRegex = regexp.MustCompile(`(?:https://t\.me/proxy\?|tg://proxy\?|https://\w+\.t\.me/proxy\?)[^\s"'<>]+`)
	proxyRegex   = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b`)
)

func NewScraper(outputDir string, workers int, skipTelegram bool) *Scraper {
	return &Scraper{
		OutputDir:    outputDir,
		Workers:      workers,
		SkipTelegram: skipTelegram,
	}
}

func (s *Scraper) getRandomUserAgent() string {
	return userAgents[time.Now().UnixNano()%int64(len(userAgents))]
}

func (s *Scraper) fetchURL(urlStr string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", s.getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (s *Scraper) extractConfigsFromText(text string) (vless, vmess, trojan, ss, mtproto, proxies []string) {
	vless = vlessRegex.FindAllString(text, -1)
	vmess = vmessRegex.FindAllString(text, -1)
	trojan = trojanRegex.FindAllString(text, -1)
	ss = ssRegex.FindAllString(text, -1)
	ss = append(ss, ssrRegex.FindAllString(text, -1)...)
	mtproto = mtprotoRegex.FindAllString(text, -1)
	proxies = proxyRegex.FindAllString(text, -1)

	return
}

func (s *Scraper) DetectSourceType(url string) string {
	text, err := s.fetchURL(url)
	if err != nil {
		return "unknown"
	}

	vless, vmess, trojan, ss, mtproto, proxies := s.extractConfigsFromText(text)

	counts := map[string]int{
		"vless":   len(vless),
		"vmess":   len(vmess),
		"trojan":  len(trojan),
		"ss":      len(ss),
		"mtproto": len(mtproto),
		"proxy":   len(proxies),
	}

	maxType := "unknown"
	maxCount := 0
	for typ, count := range counts {
		if count > maxCount {
			maxCount = count
			maxType = typ
		}
	}

	if maxCount == 0 {
		return "unknown"
	}

	typeMap := map[string]string{
		"vless":   "vless",
		"vmess":   "vmess",
		"trojan":  "trojan",
		"ss":      "ss",
		"mtproto": "mtproto",
		"proxy":   "http",
	}

	if mapped, ok := typeMap[maxType]; ok {
		return mapped
	}
	return "unknown"
}

func (s *Scraper) getConfigPath() (string, error) {
	var configDir string

	if os.Getenv("TERMUX_VERSION") != "" {
		configDir = filepath.Join(os.Getenv("HOME"), ".proxy-scraper")
	} else {
		usr, err := user.Current()
		if err != nil {
			configDir = filepath.Join(os.Getenv("HOME"), ".proxy-scraper")
		} else {
			configDir = filepath.Join(usr.HomeDir, ".proxy-scraper")
		}
	}

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", err
	}

	return filepath.Join(configDir, "sources.json"), nil
}

func (s *Scraper) LoadConfig() error {
	configPath, err := s.getConfigPath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.Config = &Config{
				Configs:      defaultConfigsURLs,
				MTProto:      defaultMTProtoURLs,
				Proxies:      defaultProxyURLs,
				Telegram:     defaultTelegramChannels,
				Custom:       []SourceConfig{},
				SkipTelegram: false,
			}
			return nil
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	if len(config.Configs) == 0 {
		config.Configs = defaultConfigsURLs
	}
	if len(config.MTProto) == 0 {
		config.MTProto = defaultMTProtoURLs
	}
	if len(config.Proxies) == 0 {
		config.Proxies = defaultProxyURLs
	}
	if len(config.Telegram) == 0 {
		config.Telegram = defaultTelegramChannels
	}

	s.Config = &config
	return nil
}

func (s *Scraper) SaveConfig() error {
	if s.Config == nil {
		return fmt.Errorf("config not loaded")
	}

	configPath, err := s.getConfigPath()
	if err != nil {
		return err
	}

	s.Config.LastRun = time.Now().Format(time.RFC3339)

	data, err := json.MarshalIndent(s.Config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

func (s *Scraper) ShowConfig() error {
	configPath, err := s.getConfigPath()
	if err != nil {
		return err
	}

	if err := s.LoadConfig(); err != nil {
		return err
	}

	fmt.Printf("\n%s%s=== Config File Path ===%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s%s\n\n", White, configPath, Reset)

	fmt.Printf("%s%s=== Config Summary ===%s\n", Bold, Cyan, Reset)
	fmt.Printf("%sConfigs:      %d%s\n", White, len(s.Config.Configs), Reset)
	fmt.Printf("%sMTProto:      %d%s\n", White, len(s.Config.MTProto), Reset)
	fmt.Printf("%sProxy Types:  %d%s\n", White, len(s.Config.Proxies), Reset)
	
	totalProxies := 0
	for _, urls := range s.Config.Proxies {
		totalProxies += len(urls)
	}
	fmt.Printf("%sTotal Proxies:%d%s\n", White, totalProxies, Reset)
	
	fmt.Printf("%sTelegram:     %d%s\n", White, len(s.Config.Telegram), Reset)
	fmt.Printf("%sCustom:       %d%s\n", White, len(s.Config.Custom), Reset)
	fmt.Printf("%sSkip Telegram:%v%s\n", White, s.Config.SkipTelegram, Reset)
	fmt.Printf("%sLast Run:     %s%s\n\n", White, s.Config.LastRun, Reset)

	if len(s.Config.Configs) > 0 {
		fmt.Printf("%s%s--- Config URLs ---%s\n", Bold, Yellow, Reset)
		for _, u := range s.Config.Configs {
			fmt.Printf("  %s- %s%s\n", Gray, White, u)
		}
		fmt.Println()
	}

	if len(s.Config.MTProto) > 0 {
		fmt.Printf("%s%s--- MTProto URLs ---%s\n", Bold, Yellow, Reset)
		for _, u := range s.Config.MTProto {
			fmt.Printf("  %s- %s%s\n", Gray, White, u)
		}
		fmt.Println()
	}

	if len(s.Config.Proxies) > 0 {
		fmt.Printf("%s%s--- Proxy URLs ---%s\n", Bold, Yellow, Reset)
		for pType, urls := range s.Config.Proxies {
			fmt.Printf("  %s[%s] (%d URLs)%s\n", Magenta, pType, len(urls), Reset)
			for _, u := range urls {
				fmt.Printf("    %s- %s%s\n", Gray, White, u)
			}
		}
		fmt.Println()
	}

	if len(s.Config.Telegram) > 0 {
		fmt.Printf("%s%s--- Telegram Channels ---%s\n", Bold, Yellow, Reset)
		for _, u := range s.Config.Telegram {
			fmt.Printf("  %s- %s%s\n", Gray, White, u)
		}
		fmt.Println()
	}

	if len(s.Config.Custom) > 0 {
		fmt.Printf("%s%s--- Custom Sources ---%s\n", Bold, Yellow, Reset)
		for _, custom := range s.Config.Custom {
			fmt.Printf("  %s[Type: %s] (%d URLs)%s\n", Magenta, custom.PType, len(custom.URLs), Reset)
			for _, u := range custom.URLs {
				fmt.Printf("    %s- %s%s\n", Gray, White, u)
			}
		}
		fmt.Println()
	}

	return nil
}

func (s *Scraper) AddSource(url string, sourceType string) error {
	if s.Config == nil {
		if err := s.LoadConfig(); err != nil {
			return err
		}
	}

	if sourceType == "" || sourceType == "auto" {
		fmt.Printf("%s[ℹ] Auto-detecting type for: %s%s\n", Blue, url, Reset)
		sourceType = s.DetectSourceType(url)
		if sourceType == "unknown" {
			return fmt.Errorf("could not detect source type for %s", url)
		}
		fmt.Printf("%s[✓] Detected type: %s%s\n", Green, sourceType, Reset)
	}

	switch sourceType {
	case "vless", "vmess", "trojan", "ss", "ssr":
		s.Config.Configs = append(s.Config.Configs, url)
	case "mtproto":
		s.Config.MTProto = append(s.Config.MTProto, url)
	case "http", "https", "socks4", "socks5":
		if s.Config.Proxies == nil {
			s.Config.Proxies = make(map[string][]string)
		}
		s.Config.Proxies[sourceType] = append(s.Config.Proxies[sourceType], url)
	default:
		s.Config.Custom = append(s.Config.Custom, SourceConfig{
			URLs:  []string{url},
			PType: sourceType,
		})
	}

	return s.SaveConfig()
}


func (s *Scraper) RemoveSource(urlToRemove string) error {
	if s.Config == nil {
		if err := s.LoadConfig(); err != nil {
			return err
		}
	}

	removed := false

	newConfigs := []string{}
	for _, u := range s.Config.Configs {
		if u != urlToRemove {
			newConfigs = append(newConfigs, u)
		} else {
			removed = true
		}
	}
	s.Config.Configs = newConfigs

	newMTProto := []string{}
	for _, u := range s.Config.MTProto {
		if u != urlToRemove {
			newMTProto = append(newMTProto, u)
		} else {
			removed = true
		}
	}
	s.Config.MTProto = newMTProto

	for pType, urls := range s.Config.Proxies {
		newURLs := []string{}
		for _, u := range urls {
			if u != urlToRemove {
				newURLs = append(newURLs, u)
			} else {
				removed = true
			}
		}
		s.Config.Proxies[pType] = newURLs
	}

	newTelegram := []string{}
	for _, u := range s.Config.Telegram {
		if u != urlToRemove {
			newTelegram = append(newTelegram, u)
		} else {
			removed = true
		}
	}
	s.Config.Telegram = newTelegram

	newCustom := []SourceConfig{}
	for _, custom := range s.Config.Custom {
		newURLs := []string{}
		for _, u := range custom.URLs {
			if u != urlToRemove {
				newURLs = append(newURLs, u)
			} else {
				removed = true
			}
		}
		if len(newURLs) > 0 {
			newCustom = append(newCustom, SourceConfig{
				URLs:  newURLs,
				PType: custom.PType,
			})
		}
	}
	s.Config.Custom = newCustom

	if !removed {
		return fmt.Errorf("URL not found in config: %s", urlToRemove)
	}

	fmt.Printf("%s[✓] Removed URL from config: %s%s\n", Green, urlToRemove, Reset)
	return s.SaveConfig()
}

func (s *Scraper) ReloadConfig() error {
	configPath, err := s.getConfigPath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(configPath); err == nil {
		if err := os.Remove(configPath); err != nil {
			return fmt.Errorf("failed to delete config file: %v", err)
		}
		fmt.Printf("%s[✓] Deleted old config file%s\n", Green, Reset)
	}

	s.Config = nil
	if err := s.LoadConfig(); err != nil {
		return err
	}

	fmt.Printf("%s[✓] Config reloaded successfully%s\n", Green, Reset)
	return nil
}

func removeDuplicates(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func (s *Scraper) worker(id int, jobs <-chan Job, results chan<- ScrapeResult, wg *sync.WaitGroup, totalJobs *int64, completedJobs *int64) {
	defer wg.Done()

	for job := range jobs {
		fmt.Printf("%s[Worker %d] Scraping %s: %s%s\n", Cyan, id, job.kind, job.name, Reset)

		text, err := s.fetchURL(job.url)
		if err != nil {
			fmt.Printf("%s[Worker %d] [✗] Failed: %s - %v%s\n", Red, id, job.name, err, Reset)
			results <- ScrapeResult{Items: []string{}, SourceType: job.sourceType, Error: err}
		} else {
			vless, vmess, trojan, ss, mtproto, proxies := s.extractConfigsFromText(text)
			allItems := append(append(append(append(append(vless, vmess...), trojan...), ss...), mtproto...), proxies...)
			fmt.Printf("%s[Worker %d] [✓] Success: %s (vless:%d vmess:%d trojan:%d ss:%d mtproto:%d proxy:%d)%s\n",
				Green, id, job.name, len(vless), len(vmess), len(trojan), len(ss), len(mtproto), len(proxies), Reset)
			results <- ScrapeResult{Items: allItems, SourceType: job.sourceType, Error: nil}
		}

		completed := atomic.AddInt64(completedJobs, 1)
		percent := float64(completed) / float64(*totalJobs) * 100
		fmt.Printf("%s[Progress] %d/%d (%.1f%%)%s\n", Yellow, completed, *totalJobs, percent, Reset)
	}
}

func (s *Scraper) saveResults(vless, vmess, trojan, ss, mtproto, proxies map[string][]string) error {
	if err := os.MkdirAll(s.OutputDir, 0755); err != nil {
		return err
	}

	files := map[string][]string{
		filepath.Join(s.OutputDir, "vless.txt"):    vless["items"],
		filepath.Join(s.OutputDir, "vmess.txt"):    vmess["items"],
		filepath.Join(s.OutputDir, "trojan.txt"):   trojan["items"],
		filepath.Join(s.OutputDir, "ss.txt"):      ss["items"],
		filepath.Join(s.OutputDir, "mtproto.txt"): mtproto["items"],
		filepath.Join(s.OutputDir, "http.txt"):    proxies["http"],
		filepath.Join(s.OutputDir, "https.txt"):   proxies["https"],
		filepath.Join(s.OutputDir, "socks4.txt"):  proxies["socks4"],
		filepath.Join(s.OutputDir, "socks5.txt"):  proxies["socks5"],
	}

	for filename, data := range files {
		if len(data) == 0 {
			continue
		}

		content := strings.Join(data, "\n")
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			return fmt.Errorf("error writing %s: %v", filename, err)
		}
		fmt.Printf("%s[✓] Saved %d items to %s%s\n", Green, len(data), filename, Reset)
	}

	return nil
}

func (s *Scraper) Run() error {
	if s.Config == nil {
		if err := s.LoadConfig(); err != nil {
			return err
		}
	}

	fmt.Printf("%s%s╔════════════════════════════════════════╗%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s%s║     Proxy Scraper - Starting...      ║%s\n", Bold, White, Reset)
	fmt.Printf("%s%s╚════════════════════════════════════════╝%s\n", Bold, Cyan, Reset)

	fmt.Printf("%s[ℹ] Workers: %d%s\n", Blue, s.Workers, Reset)
	fmt.Printf("%s[ℹ] Config URLs: %d%s\n", Blue, len(s.Config.Configs), Reset)
	fmt.Printf("%s[ℹ] MTProto URLs: %d%s\n", Blue, len(s.Config.MTProto), Reset)
	fmt.Printf("%s[ℹ] Proxy Types: %d%s\n", Blue, len(s.Config.Proxies), Reset)
	fmt.Printf("%s[ℹ] Telegram Channels: %d%s\n", Blue, len(s.Config.Telegram), Reset)
	if len(s.Config.Custom) > 0 {
		fmt.Printf("%s[ℹ] Custom Sources: %d%s\n", Blue, len(s.Config.Custom), Reset)
	}
	fmt.Println()

	var wg sync.WaitGroup
	var totalJobs int64
	var completedJobs int64

	jobs := make(chan Job, 100)
	results := make(chan ScrapeResult, 100)

	resultsMap := struct {
		Vless   map[string][]string
		Vmess   map[string][]string
		Trojan  map[string][]string
		SS      map[string][]string
		MTProto map[string][]string
		Proxies map[string][]string
	}{
		Vless:   make(map[string][]string),
		Vmess:   make(map[string][]string),
		Trojan:  make(map[string][]string),
		SS:      make(map[string][]string),
		MTProto: make(map[string][]string),
		Proxies: make(map[string][]string),
	}

	resultsMap.Vless["items"] = []string{}
	resultsMap.Vmess["items"] = []string{}
	resultsMap.Trojan["items"] = []string{}
	resultsMap.SS["items"] = []string{}
	resultsMap.MTProto["items"] = []string{}
	resultsMap.Proxies["http"] = []string{}
	resultsMap.Proxies["https"] = []string{}
	resultsMap.Proxies["socks4"] = []string{}
	resultsMap.Proxies["socks5"] = []string{}

	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go s.worker(i+1, jobs, results, &wg, &totalJobs, &completedJobs)
	}

	go func() {
		for _, u := range s.Config.Configs {
			atomic.AddInt64(&totalJobs, 1)
			jobs <- Job{url: u, name: u, kind: "config", sourceType: "config"}
		}

		for _, u := range s.Config.MTProto {
			atomic.AddInt64(&totalJobs, 1)
			jobs <- Job{url: u, name: u, kind: "mtproto", sourceType: "mtproto"}
		}

		for pType, urls := range s.Config.Proxies {
			for _, u := range urls {
				atomic.AddInt64(&totalJobs, 1)
				jobs <- Job{url: u, name: u, kind: fmt.Sprintf("proxy-%s", pType), sourceType: pType}
			}
		}

		if !s.SkipTelegram {
			for _, u := range s.Config.Telegram {
				atomic.AddInt64(&totalJobs, 1)
				jobs <- Job{url: u, name: u, kind: "telegram", sourceType: "telegram"}
			}
		}

		for _, custom := range s.Config.Custom {
			for _, u := range custom.URLs {
				atomic.AddInt64(&totalJobs, 1)
				jobs <- Job{url: u, name: u, kind: fmt.Sprintf("custom-%s", custom.PType), sourceType: custom.PType}
			}
		}

		close(jobs)
	}()

	wg.Wait()
	close(results)

	for result := range results {
		if result.Error != nil {
			continue
		}

		if result.SourceType != "" && (result.SourceType == "http" || result.SourceType == "https" || result.SourceType == "socks4" || result.SourceType == "socks5") {
			for _, item := range result.Items {
				if strings.Contains(item, ":") && proxyRegex.MatchString(item) {
					resultsMap.Proxies[result.SourceType] = append(resultsMap.Proxies[result.SourceType], item)
				}
			}
		} else {
			for _, item := range result.Items {
				if strings.HasPrefix(item, "vless://") {
					resultsMap.Vless["items"] = append(resultsMap.Vless["items"], item)
				} else if strings.HasPrefix(item, "vmess://") {
					resultsMap.Vmess["items"] = append(resultsMap.Vmess["items"], item)
				} else if strings.HasPrefix(item, "trojan://") {
					resultsMap.Trojan["items"] = append(resultsMap.Trojan["items"], item)
				} else if strings.HasPrefix(item, "ss://") || strings.HasPrefix(item, "ssr://") {
					resultsMap.SS["items"] = append(resultsMap.SS["items"], item)
				} else if strings.Contains(item, "t.me/proxy") || strings.Contains(item, "tg://proxy") {
					resultsMap.MTProto["items"] = append(resultsMap.MTProto["items"], item)
				} else if strings.Contains(item, ":") && proxyRegex.MatchString(item) {
					resultsMap.Proxies["http"] = append(resultsMap.Proxies["http"], item)
				}
			}
		}
	}

	resultsMap.Vless["items"] = removeDuplicates(resultsMap.Vless["items"])
	resultsMap.Vmess["items"] = removeDuplicates(resultsMap.Vmess["items"])
	resultsMap.Trojan["items"] = removeDuplicates(resultsMap.Trojan["items"])
	resultsMap.SS["items"] = removeDuplicates(resultsMap.SS["items"])
	resultsMap.MTProto["items"] = removeDuplicates(resultsMap.MTProto["items"])
	resultsMap.Proxies["http"] = removeDuplicates(resultsMap.Proxies["http"])
	resultsMap.Proxies["https"] = removeDuplicates(resultsMap.Proxies["https"])
	resultsMap.Proxies["socks4"] = removeDuplicates(resultsMap.Proxies["socks4"])
	resultsMap.Proxies["socks5"] = removeDuplicates(resultsMap.Proxies["socks5"])

	return s.saveResults(resultsMap.Vless, resultsMap.Vmess, resultsMap.Trojan, resultsMap.SS, resultsMap.MTProto, resultsMap.Proxies)

	fmt.Println()
	fmt.Printf("%s%s╔════════════════════════════════════════╗%s\n", Bold, Green, Reset)
	fmt.Printf("%s%s║         Scraping Completed!            ║%s\n", Bold, White, Reset)
	fmt.Printf("%s%s╚════════════════════════════════════════╝%s\n", Bold, Green, Reset)
	fmt.Println()

	if err := s.saveResults(
		resultsMap.Vless,
		resultsMap.Vmess,
		resultsMap.Trojan,
		resultsMap.SS,
		resultsMap.MTProto,
		resultsMap.Proxies,
	); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("%s%s=== Summary ===%s\n", Bold, Cyan, Reset)
	fmt.Printf("%sVLESS: %d%s\n", White, len(resultsMap.Vless["items"]), Reset)
	fmt.Printf("%sVMESS: %d%s\n", White, len(resultsMap.Vmess["items"]), Reset)
	fmt.Printf("%sTrojan: %d%s\n", White, len(resultsMap.Trojan["items"]), Reset)
	fmt.Printf("%sSS/SSR: %d%s\n", White, len(resultsMap.SS["items"]), Reset)
	fmt.Printf("%sMTProto: %d%s\n", White, len(resultsMap.MTProto["items"]), Reset)
	fmt.Printf("%sHTTP: %d%s\n", White, len(resultsMap.Proxies["http"]), Reset)
	fmt.Printf("%sHTTPS: %d%s\n", White, len(resultsMap.Proxies["https"]), Reset)
	fmt.Printf("%sSOCKS4: %d%s\n", White, len(resultsMap.Proxies["socks4"]), Reset)
	fmt.Printf("%sSOCKS5: %d%s\n", White, len(resultsMap.Proxies["socks5"]), Reset)
	fmt.Printf("%s===============\n%s", White, Reset)

	return nil
}
