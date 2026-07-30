package cf

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"gopkg.in/yaml.v3"
)

const (
	CloudflareASN = 13335
	BufferSize    = 10000
)


type ScanResult struct {
	IP           string `json:"ip" yaml:"ip" csv:"ip"`
	Port         int    `json:"port" yaml:"port" csv:"port"`
	IsAlive      bool   `json:"is_alive" yaml:"is_alive" csv:"is_alive"`
	IsCloudflare bool   `json:"is_cloudflare" yaml:"is_cloudflare" csv:"is_cloudflare"`
	Score        int    `json:"score" yaml:"score" csv:"score"`
	Source       string `json:"source" yaml:"source" csv:"source"`
	Country      string `json:"country" yaml:"country" csv:"country"`
	City         string `json:"city" yaml:"city" csv:"city"`
	Region       string `json:"region" yaml:"region" csv:"region"`
	ASN          string `json:"asn" yaml:"asn" csv:"asn"`
	Hostname     string `json:"hostname" yaml:"hostname" csv:"hostname"`

	CloudflareConfidence int `json:"cloudflare_confidence" yaml:"cloudflare_confidence" csv:"cloudflare_confidence"`

	IsGenuineCFRange bool `json:"is_genuine_cf_range" yaml:"is_genuine_cf_range" csv:"is_genuine_cf_range"`

	IsProxy bool `json:"is_proxy" yaml:"is_proxy" csv:"is_proxy"`

	Datacenter string `json:"datacenter" yaml:"datacenter" csv:"datacenter"`
	EdgeType   string `json:"edge_type" yaml:"edge_type" csv:"edge_type"`

	TLSVersion  string `json:"tls_version" yaml:"tls_version" csv:"tls_version"`
	TLSCipher   string `json:"tls_cipher" yaml:"tls_cipher" csv:"tls_cipher"`
	TLSALPN     string `json:"tls_alpn" yaml:"tls_alpn" csv:"tls_alpn"`
	TLSSNI      string `json:"tls_sni" yaml:"tls_sni" csv:"tls_sni"`
	CertIssuer  string `json:"cert_issuer" yaml:"cert_issuer" csv:"cert_issuer"`
	CertSAN     string `json:"cert_san" yaml:"cert_san" csv:"cert_san"`

	TLSFingerprint string `json:"tls_fingerprint" yaml:"tls_fingerprint" csv:"tls_fingerprint"`

	CertExpiry time.Time `json:"cert_expiry" yaml:"cert_expiry" csv:"cert_expiry"`

	HTTPVersion    string `json:"http_version" yaml:"http_version" csv:"http_version"`
	HTTP2Supported bool   `json:"http2_supported" yaml:"http2_supported" csv:"http2_supported"`
	HTTP3Supported bool   `json:"http3_supported" yaml:"http3_supported" csv:"http3_supported"`
	HTTP11         bool   `json:"http11" yaml:"http11" csv:"http11"`

	CFRay         string `json:"cf_ray" yaml:"cf_ray" csv:"cf_ray"`
	CFCacheStatus string `json:"cf_cache_status" yaml:"cf_cache_status" csv:"cf_cache_status"`
	ServerHeader  string `json:"server_header" yaml:"server_header" csv:"server_header"`
	CFRequestID   string `json:"cf_request_id" yaml:"cf_request_id" csv:"cf_request_id"`

	TCPConnectMs   float64 `json:"tcp_connect_ms" yaml:"tcp_connect_ms" csv:"tcp_connect_ms"`
	TLSHandshakeMs float64 `json:"tls_handshake_ms" yaml:"tls_handshake_ms" csv:"tls_handshake_ms"`
	QUICHandshakeMs float64 `json:"quic_handshake_ms" yaml:"quic_handshake_ms" csv:"quic_handshake_ms"`
	TTFBMs         float64 `json:"ttfb_ms" yaml:"ttfb_ms" csv:"ttfb_ms"`
	DownloadMs     float64 `json:"download_ms" yaml:"download_ms" csv:"download_ms"`

	DownloadSpeed1MB  float64 `json:"download_speed_1mb" yaml:"download_speed_1mb" csv:"download_speed_1mb"`
	DownloadSpeed10MB float64 `json:"download_speed_10mb" yaml:"download_speed_10mb" csv:"download_speed_10mb"`

	PacketLoss float64 `json:"packet_loss" yaml:"packet_loss" csv:"packet_loss"`
	TCPFailureRate float64 `json:"tcp_failure_rate" yaml:"tcp_failure_rate" csv:"tcp_failure_rate"`

	AverageLatency float64 `json:"average_latency" yaml:"average_latency" csv:"average_latency"`
	MedianLatency  float64 `json:"median_latency" yaml:"median_latency" csv:"median_latency"`
	Jitter float64 `json:"jitter" yaml:"jitter" csv:"jitter"`

	Ports     []int     `json:"ports" yaml:"ports" csv:"ports"`
	ScannedAt time.Time `json:"scanned_at" yaml:"scanned_at" csv:"scanned_at"`
}

type ScoreWeights struct {
	Latency      float64 `yaml:"latency"`
	Reliability  float64 `yaml:"reliability"`
	HTTP3        float64 `yaml:"http3"`
	TLS          float64 `yaml:"tls"`
	Speed        float64 `yaml:"speed"`
	Cloudflare   float64 `yaml:"cloudflare"`
	LatencyRefMs float64 `yaml:"latency_ref_ms"`
	SpeedRefMBps float64 `yaml:"speed_ref_mbps"`
}

func defaultScoreWeights() ScoreWeights {
	return ScoreWeights{
		Latency:      30,
		Reliability:  20,
		HTTP3:        10,
		TLS:          10,
		Speed:        20,
		Cloudflare:   10,
		LatencyRefMs: 300,
		SpeedRefMBps: 50,
	}
}

func loadScoreWeights(path string) (ScoreWeights, error) {
	weights := defaultScoreWeights()
	if path == "" {
		return weights, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return weights, err
	}
	if err := yaml.Unmarshal(data, &weights); err != nil {
		return weights, err
	}
	return weights, nil
}

type ScanConfig struct {
	Sources          []string
	WorkerCount      int
	Ports            []int
	EnableHTTP2      bool
	EnableHTTP3      bool
	EnableSpeedTest  bool
	EnablePacketLoss bool
	EnableGeoIP      bool
	EnableReverseDNS bool
	GeoIPDBPath      string
	ASNDBPath        string
	OutputFormat     string
	OutputPath       string
	TestDomain       string

	SpeedTestHost      string
	RateLimit          int
	RealTimePrint      bool
	ShowProgress       bool
	MaxResults         int
	Timeout            int
	PortScanTimeout    int
	SortBy             string
	NoColor            bool
	MaxIPsPerRange     int
	RandomSample       bool
	ShuffleIPs         bool
	LatencySamples     int
	SaveValidIPs       bool
	StopAfterGood      int
	GoodScoreThreshold int
	ScoreWeights       ScoreWeights
	ScoreConfigPath    string
}

type WorkerPool struct {
	workers    int
	jobs       chan net.IP
	results    chan ScanResult
	ctx        context.Context
	cancel     context.CancelFunc
	config     *ScanConfig
	geoDB      *geoip2.Reader
	asnDB      *geoip2.Reader
	limiter    *rateLimiter
	scanned    sync.Map
	stats      *ScanStats
	printMu    sync.Mutex
	lastPrint  time.Time
	startTime  time.Time
	topResults []ScanResult
	topMu      sync.Mutex
	validFile  *os.File
	validMu    sync.Mutex
	goodCount  int64

	cfRanges []*net.IPNet
}

type ScanStats struct {
	Total       int64
	Scanned     int64
	Alive       int64
	Dead        int64
	HTTP3       int64
	BestLatency float64
	mu          sync.Mutex
}

func (s *ScanStats) Snapshot() (total, scanned, alive, dead, http3 int64, best float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Total, s.Scanned, s.Alive, s.Dead, s.HTTP3, s.BestLatency
}

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[97m"
	Bold    = "\033[1m"
)

type rateLimiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newRateLimiter(perSecond int) *rateLimiter {
	if perSecond <= 0 {
		return nil
	}
	rl := &rateLimiter{
		tokens: make(chan struct{}, perSecond),
		stop:   make(chan struct{}),
	}
	interval := time.Second / time.Duration(perSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-rl.stop:
				return
			case <-ticker.C:
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return rl
}

func (rl *rateLimiter) Wait(ctx context.Context) {
	if rl == nil {
		return
	}
	select {
	case <-rl.tokens:
	case <-ctx.Done():
	}
}

func (rl *rateLimiter) Close() {
	if rl == nil {
		return
	}
	close(rl.stop)
}

func NewWorkerPool(config *ScanConfig, geoDB *geoip2.Reader, asnDB *geoip2.Reader) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	var validFile *os.File
	if config.SaveValidIPs {
		timestamp := time.Now().Format("20060102_150405")
		validFileName := fmt.Sprintf("valid_ips_%s.txt", timestamp)
		validFile, _ = os.OpenFile(validFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	}

	return &WorkerPool{
		workers:    config.WorkerCount,
		jobs:       make(chan net.IP, BufferSize),
		results:    make(chan ScanResult, BufferSize),
		ctx:        ctx,
		cancel:     cancel,
		config:     config,
		geoDB:      geoDB,
		asnDB:      asnDB,
		limiter:    newRateLimiter(config.RateLimit),
		stats:      &ScanStats{},
		startTime:  time.Now(),
		topResults: make([]ScanResult, 0, config.MaxResults),
		validFile:  validFile,
		cfRanges:   fetchOfficialCFRanges(),
	}
}

func (wp *WorkerPool) Start(wg *sync.WaitGroup) {
	for i := 0; i < wp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wp.worker()
		}()
	}
}

func (wp *WorkerPool) worker() {
	for {
		select {
		case <-wp.ctx.Done():
			return
		case ip, ok := <-wp.jobs:
			if !ok {
				return
			}

			wp.limiter.Wait(wp.ctx)
			if wp.ctx.Err() != nil {
				return
			}

			result := wp.scanIP(ip)
			select {
			case wp.results <- result:
			case <-wp.ctx.Done():
				return
			}
			wp.updateStats(result)

			if result.IsAlive {
				wp.saveValidIP(result)
				wp.updateTopResults(result)
				if wp.config.RealTimePrint {
					wp.maybePrintTopResults()
				}
				if wp.config.StopAfterGood > 0 && result.Score >= wp.config.GoodScoreThreshold {
					if atomic.AddInt64(&wp.goodCount, 1) >= int64(wp.config.StopAfterGood) {
						wp.cancel()
					}
				}
			}
		}
	}
} 

func (wp *WorkerPool) saveValidIP(result ScanResult) {
	if wp.validFile == nil {
		return
	}
	wp.validMu.Lock()
	defer wp.validMu.Unlock()
	line := fmt.Sprintf("%s:%d\n", result.IP, result.Port)
	wp.validFile.WriteString(line)
	wp.validFile.Sync()
}

func (wp *WorkerPool) updateTopResults(result ScanResult) {
	wp.topMu.Lock()
	defer wp.topMu.Unlock()

	for i, r := range wp.topResults {
		if r.IP == result.IP && r.Port == result.Port {
			wp.topResults[i] = result
			wp.sortTopResultsLocked()
			return
		}
	}

	wp.topResults = append(wp.topResults, result)
	wp.sortTopResultsLocked()

	if len(wp.topResults) > wp.config.MaxResults {
		wp.topResults = wp.topResults[:wp.config.MaxResults]
	}
}

func (wp *WorkerPool) sortTopResultsLocked() {
	sortScanResults(wp.topResults, wp.config.SortBy)
}

func sortScanResults(results []ScanResult, sortBy string) {
	sort.Slice(results, func(i, j int) bool {
		if sortBy == "latency" {
			if results[i].TCPConnectMs != results[j].TCPConnectMs {
				return results[i].TCPConnectMs < results[j].TCPConnectMs
			}
			return results[i].Score > results[j].Score
		}
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].TCPConnectMs < results[j].TCPConnectMs
	})
}

func (wp *WorkerPool) maybePrintTopResults() {
	wp.printMu.Lock()
	if time.Since(wp.lastPrint) < 150*time.Millisecond {
		wp.printMu.Unlock()
		return
	}
	wp.lastPrint = time.Now()
	wp.printMu.Unlock()
	wp.printTopResults()
}

func (wp *WorkerPool) printTopResults() {
	wp.topMu.Lock()
	top := make([]ScanResult, len(wp.topResults))
	copy(top, wp.topResults)
	wp.topMu.Unlock()

	fmt.Print("\033[H\033[2J")

	red, green, yellow, blue, cyan, white, magenta, reset := Red, Green, Yellow, Blue, Cyan, White, Magenta, Reset
	if wp.config.NoColor {
		red, green, yellow, blue, cyan, white, magenta, reset = "", "", "", "", "", "", "", ""
	}

	total, scanned, alive, dead, http3, _ := wp.stats.Snapshot()

	fmt.Printf("%s╔════════════════════════════════════════════════════════════════════════════%s╗%s\n", cyan, cyan, reset)
	fmt.Printf("%s║                     %sCloudflare Scanner - Top %d Valid IPs%s                  %s║%s\n",
		cyan, yellow, wp.config.MaxResults, reset, cyan, reset)
	fmt.Printf("%s╠════════════════════════════════════════════════════════════════════════════%s╣%s\n", cyan, cyan, reset)

	elapsed := time.Since(wp.startTime)
	percent := 0.0
	if total > 0 {
		percent = float64(scanned) / float64(total) * 100
	}
	eta := wp.estimateETA()

	progressColor := green
	if percent < 30 {
		progressColor = red
	} else if percent < 70 {
		progressColor = yellow
	}

	etaStr := eta.Round(time.Second).String()
	if eta == 0 {
		etaStr = "calculating"
	}

	fmt.Printf("%s║%s %sProgress:%s %s%6.1f%%%s  %sAlive:%s %s%5d%s  %sDead:%s %s%5d%s  %sH3:%s %s%4d%s  %sETA:%s %s%9s%s     %s║%s\n",
		cyan, reset,
		magenta, reset, progressColor, percent, reset,
		green, reset, green, alive, reset,
		red, reset, red, dead, reset,
		blue, reset, blue, http3, reset,
		yellow, reset, yellow, etaStr, reset,
		cyan, reset)

	fmt.Printf("%s╠════════════════════════════════════════════════════════════════════════════%s╣%s\n", cyan, cyan, reset)

	if len(top) == 0 {
		fmt.Printf("%s║ %-82s ║%s\n", cyan, "  Waiting for results...", reset)
	} else {
		for i, r := range top {
			if i >= wp.config.MaxResults {
				break
			}

			scoreColor := green
			if r.Score < 40 {
				scoreColor = red
			} else if r.Score < 70 {
				scoreColor = yellow
			}

			cfColor, cfText := red, "✗"
			if r.IsCloudflare {
				cfColor, cfText = green, "✓"
			}

			h2Color, h2Text := red, "✗"
			if r.HTTP2Supported {
				h2Color, h2Text = green, "✓"
			}

			h3Color, h3Text := red, "✗"
			if r.HTTP3Supported {
				h3Color, h3Text = green, "✓"
			}

			latColor := green
			if r.TCPConnectMs > 300 {
				latColor = red
			} else if r.TCPConnectMs > 150 {
				latColor = yellow
			}

			fmt.Printf("%s║ %s#%-2d%s %s%-15s%s %s:%-5d%s %sScore:%s%3d%s  %sLat:%s%7.2fms%s  %sCF:%s%s%s(%d%%) %sH2:%s%s%s %sH3:%s%s%s   %s║%s\n",
				cyan,
				magenta, i+1, reset,
				green, r.IP, reset,
				yellow, r.Port, reset,
				white, scoreColor, r.Score, reset,
				white, latColor, r.TCPConnectMs, reset,
				white, cfColor, cfText, reset, r.CloudflareConfidence,
				white, h2Color, h2Text, reset,
				white, h3Color, h3Text, reset,
				cyan, reset)
		}
	}

	fmt.Printf("%s╚════════════════════════════════════════════════════════════════════════════%s╝%s\n", cyan, cyan, reset)

	fmt.Printf("%sTotal Scanned:%s %s%d%s  |  %sValid saved to:%s %svalid_ips_*.txt%s\n",
		cyan, reset,
		green, scanned, reset,
		cyan, reset,
		yellow, reset)

	fmt.Printf("%sElapsed:%s %s%s%s  |  %sSort:%s %s%s%s  |  %sPress Ctrl+C to stop%s\n",
		cyan, reset,
		yellow, elapsed.Round(time.Second).String(), reset,
		cyan, reset,
		green, wp.config.SortBy, reset,
		yellow, reset)
}

func (wp *WorkerPool) estimateETA() time.Duration {
	total, scanned, _, _, _, _ := wp.stats.Snapshot()
	if scanned == 0 {
		return 0
	}
	elapsed := time.Since(wp.startTime)
	rate := float64(scanned) / elapsed.Seconds()
	if rate <= 0 {
		return 0
	}
	remain := float64(total - scanned)
	if remain < 0 {
		remain = 0
	}
	return time.Duration(remain/rate) * time.Second
}

func (wp *WorkerPool) printProgress() {
	wp.printMu.Lock()
	defer wp.printMu.Unlock()

	total, scanned, alive, dead, http3, _ := wp.stats.Snapshot()
	elapsed := time.Since(wp.startTime)
	percent := 0.0
	if total > 0 {
		percent = float64(scanned) / float64(total) * 100
	}
	eta := wp.estimateETA()
	etaStr := eta.Round(time.Second).String()
	if eta == 0 {
		etaStr = "calculating"
	}

	fmt.Printf("\r[%d/%d] %.1f%%  Alive:%d  Dead:%d  H3:%d  ETA:%s  Elapsed:%s",
		scanned, total, percent, alive, dead, http3, etaStr, elapsed.Round(time.Second))
}

func (wp *WorkerPool) updateStats(result ScanResult) {
	wp.stats.mu.Lock()
	defer wp.stats.mu.Unlock()
	wp.stats.Scanned++
	if result.IsAlive {
		wp.stats.Alive++
		if result.TCPConnectMs < wp.stats.BestLatency || wp.stats.BestLatency == 0 {
			wp.stats.BestLatency = result.TCPConnectMs
		}
	} else {
		wp.stats.Dead++
	}
	if result.HTTP3Supported {
		wp.stats.HTTP3++
	}
}

func (wp *WorkerPool) scanIP(ip net.IP) ScanResult {
	result := ScanResult{
		IP:        ip.String(),
		Source:    "cloudflare",
		ScannedAt: time.Now(),
	}

	if _, alreadyScanned := wp.scanned.LoadOrStore(result.IP, true); alreadyScanned {
		return result
	}

	ports := wp.config.Ports
	if len(ports) == 0 {
		ports = []int{443}
	}

	type portProbe struct {
		port    int
		latency float64
		ok      bool
	}

	probes := make(chan portProbe, len(ports))
	var pwg sync.WaitGroup
	for _, p := range ports {
		pwg.Add(1)
		go func(port int) {
			defer pwg.Done()
			ok, lat := wp.probeTCP(ip, port)
			probes <- portProbe{port: port, latency: lat, ok: ok}
		}(p)
	}
	go func() {
		pwg.Wait()
		close(probes)
	}()

	bestLatency := math.MaxFloat64
	for pr := range probes {
		if !pr.ok {
			continue
		}
		result.IsAlive = true
		result.Ports = append(result.Ports, pr.port)
		if pr.latency < bestLatency {
			bestLatency = pr.latency
			result.Port = pr.port
			result.TCPConnectMs = pr.latency
		}
	}

	if !result.IsAlive {
		return result
	}
	sort.Ints(result.Ports)

	wp.probeHTTP(ip, result.Port, &result)
	httpValidated := result.TTFBMs > 0 || result.CFRay != "" || result.ServerHeader != ""

	if httpValidated {
		var wg sync.WaitGroup
		if wp.config.EnableHTTP3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				wp.testHTTP3(ip, result.Port, &result)
			}()
		}
		if wp.config.EnableReverseDNS {
			wg.Add(1)
			go func() {
				defer wg.Done()
				wp.getReverseDNS(ip, &result)
			}()
		}
		wg.Wait()
	}

	if wp.config.EnableGeoIP && wp.geoDB != nil {
		wp.getGeoIP(ip, &result)
	}

	wp.classifyOrigin(&result)
	wp.detectDatacenter(&result)
	wp.getASN(ip, &result)

	if httpValidated {
		latencies, failures := wp.rttSamples(ip, result.Port)
		wp.applyLatencyStats(latencies, failures, &result)

		if wp.config.EnablePacketLoss {
			if loss, ok := icmpPacketLoss(ip, 10, 1500*time.Millisecond); ok {
				result.PacketLoss = loss
			} else {
				result.PacketLoss = -1
			}
		} else {
			result.PacketLoss = -1
		}

		if wp.config.EnableSpeedTest {
			wp.testSpeed(ip, result.Port, &result)
		}
	} else {
		result.PacketLoss = -1
	}

	result.Score = wp.calculateScore(&result)
	return result
}

func (wp *WorkerPool) probeTCP(ip net.IP, port int) (bool, float64) {
	timeout := time.Duration(wp.config.PortScanTimeout) * time.Second
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout)
	if err != nil {
		return false, 0
	}
	defer conn.Close()
	return true, float64(time.Since(start).Microseconds()) / 1000
}

func (wp *WorkerPool) probeHTTP(ip net.IP, port int, result *ScanResult) {
	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	targetAddr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			ServerName:         wp.config.TestDomain,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, targetAddr)
		},
		DisableCompression: true,
		DisableKeepAlives:  true,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(http.MethodHead, "https://"+wp.config.TestDomain+"/", nil)
	if err != nil {
		return
	}
	req.Host = wp.config.TestDomain
	req.Header.Set("User-Agent", "CloudflareScanner/5.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	var connectStart, tlsStart time.Time

	trace := &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			if err == nil {
				result.TCPConnectMs = float64(time.Since(connectStart).Microseconds()) / 1000
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				return
			}
			result.TLSHandshakeMs = float64(time.Since(tlsStart).Microseconds()) / 1000
			result.TLSVersion = tlsVersionString(state.Version)
			result.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
			result.TLSALPN = state.NegotiatedProtocol
			result.TLSSNI = wp.config.TestDomain
			result.TLSFingerprint = simpleTLSFingerprint(state.Version, state.CipherSuite, state.NegotiatedProtocol)
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				result.CertIssuer = cert.Issuer.CommonName
				result.CertSAN = strings.Join(cert.DNSNames, ",")
				result.CertExpiry = cert.NotAfter
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	result.TTFBMs = float64(time.Since(start).Microseconds()) / 1000
	result.HTTPVersion = resp.Proto
	result.HTTP2Supported = resp.ProtoMajor == 2
	result.HTTP11 = resp.ProtoMajor == 1

	result.ServerHeader = resp.Header.Get("Server")
	result.CFRay = resp.Header.Get("CF-Ray")
	result.CFCacheStatus = resp.Header.Get("CF-Cache-Status")
	result.CFRequestID = resp.Header.Get("CF-Request-ID")

	if strings.Contains(strings.ToLower(resp.Header.Get("Alt-Svc")), "h3") {
		result.HTTP3Supported = true
	}
}

func (wp *WorkerPool) testHTTP3(ip net.IP, port int, result *ScanResult) {
	if port == 0 {
		port = 443
	}

	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	var quicStart time.Time
	var quicHandshakeMs float64
	var quicOnce sync.Once

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         wp.config.TestDomain,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			quicOnce.Do(func() { quicStart = time.Now() })
			conn, err := quic.DialAddr(ctx, target, tlsConf, cfg)
			if err == nil {
				quicHandshakeMs = float64(time.Since(quicStart).Microseconds()) / 1000
			}
			return conn, err
		},
	}
	defer tr.Close()

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequest(http.MethodHead, "https://"+wp.config.TestDomain+"/", nil)
	if err != nil {
		return
	}
	req.Host = wp.config.TestDomain
	req.Header.Set("User-Agent", "CloudflareScanner/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	result.HTTP3Supported = true
	result.QUICHandshakeMs = quicHandshakeMs

	if result.HTTPVersion == "" {
		result.HTTPVersion = resp.Proto
	}
	if ray := resp.Header.Get("CF-Ray"); ray != "" && result.CFRay == "" {
		result.CFRay = ray
	}
	if cache := resp.Header.Get("CF-Cache-Status"); cache != "" && result.CFCacheStatus == "" {
		result.CFCacheStatus = cache
	}
	if server := resp.Header.Get("Server"); server != "" && result.ServerHeader == "" {
		result.ServerHeader = server
	}
	if rid := resp.Header.Get("CF-Request-ID"); rid != "" && result.CFRequestID == "" {
		result.CFRequestID = rid
	}
}

func (wp *WorkerPool) rttSamples(ip net.IP, port int) ([]float64, int) {
	n := wp.config.LatencySamples
	if n <= 0 {
		n = 4
	}

	timeout := time.Duration(wp.config.PortScanTimeout) * time.Second
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         wp.config.TestDomain,
			InsecureSkipVerify: true,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, target)
		},
		MaxIdleConnsPerHost: 1,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	defer transport.CloseIdleConnections()

	latencies := make([]float64, 0, n)
	failures := 0

	for i := 0; i < n+1; i++ {
		req, err := http.NewRequest(http.MethodHead, "https://"+wp.config.TestDomain+"/", nil)
		if err != nil {
			failures++
			continue
		}
		req.Host = wp.config.TestDomain

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			failures++
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if i == 0 {
			continue
		}
		latencies = append(latencies, float64(time.Since(start).Microseconds())/1000)
	}

	return latencies, failures
}

func (wp *WorkerPool) applyLatencyStats(latencies []float64, failures int, result *ScanResult) {
	total := len(latencies) + failures
	if total > 0 {
		result.TCPFailureRate = float64(failures) / float64(total) * 100
	}
	if len(latencies) == 0 {
		return
	}

	sorted := append([]float64(nil), latencies...)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}
	avg := sum / float64(len(sorted))
	result.AverageLatency = avg

	if len(sorted)%2 == 0 {
		result.MedianLatency = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	} else {
		result.MedianLatency = sorted[len(sorted)/2]
	}

	var variance float64
	for _, v := range sorted {
		diff := v - avg
		variance += diff * diff
	}
	variance /= float64(len(sorted))
	result.Jitter = math.Sqrt(variance)
}

func icmpPacketLoss(ip net.IP, count int, timeout time.Duration) (lossPercent float64, ok bool) {
	isV4 := ip.To4() != nil

	type netMode struct {
		network string
		raw     bool
	}
	modes := []netMode{{"udp4", false}, {"ip4:icmp", true}}
	protoICMP := 1
	if !isV4 {
		modes = []netMode{{"udp6", false}, {"ip6:ipv6-icmp", true}}
		protoICMP = 58
	}

	var conn *icmp.PacketConn
	var err error
	var usingRaw bool
	for _, m := range modes {
		listenAddr := "0.0.0.0"
		if !isV4 {
			listenAddr = "::"
		}
		conn, err = icmp.ListenPacket(m.network, listenAddr)
		if err == nil {
			usingRaw = m.raw
			break
		}
	}
	if conn == nil {
		return 0, false
	}
	defer conn.Close()

	var dst net.Addr
	if usingRaw {
		dst = &net.IPAddr{IP: ip}
	} else {
		dst = &net.UDPAddr{IP: ip}
	}

	sent := 0
	received := 0

	for seq := 0; seq < count; seq++ {
		var msgType icmp.Type
		if isV4 {
			msgType = ipv4.ICMPTypeEcho
		} else {
			msgType = ipv6.ICMPTypeEchoRequest
		}
		msg := icmp.Message{
			Type: msgType,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  seq,
				Data: []byte("cf-scanner-ping"),
			},
		}
		wb, merr := msg.Marshal(nil)
		if merr != nil {
			continue
		}

		sent++
		if _, werr := conn.WriteTo(wb, dst); werr != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(timeout))
		rb := make([]byte, 1500)
		n, _, rerr := conn.ReadFrom(rb)
		if rerr != nil {
			continue
		}

		rm, perr := icmp.ParseMessage(protoICMP, rb[:n])
		if perr != nil {
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			received++
		}
	}

	if sent == 0 {
		return 0, false
	}
	return float64(sent-received) / float64(sent) * 100, true
}

func (wp *WorkerPool) testSpeed(ip net.IP, port int, result *ScanResult) {
	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}

	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	speedHost := wp.config.SpeedTestHost
	if speedHost == "" {
		speedHost = "speed.cloudflare.com"
	}

	transport := &http.Transport{
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			ServerName:         speedHost,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, target)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	tests := []struct {
		Bytes int64
		Field *float64
	}{
		{1 * 1024 * 1024, &result.DownloadSpeed1MB},
		{10 * 1024 * 1024, &result.DownloadSpeed10MB},
	}

	for _, t := range tests {
		url := fmt.Sprintf("https://%s/__down?bytes=%d", speedHost, t.Bytes)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Host = speedHost
		req.Header.Set("User-Agent", "CloudflareScanner/5.0")
		req.Header.Set("Cache-Control", "no-cache")

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		downloaded, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil || downloaded == 0 {
			continue
		}

		elapsed := time.Since(start).Seconds()
		if elapsed <= 0 {
			continue
		}

		speedMBps := (float64(downloaded) / 1024.0 / 1024.0) / elapsed
		*t.Field = speedMBps

		if result.DownloadMs == 0 {
			result.DownloadMs = elapsed * 1000
		}
	}
}

func (wp *WorkerPool) getGeoIP(ip net.IP, result *ScanResult) {
	if wp.geoDB == nil {
		return
	}
	record, err := wp.geoDB.City(ip)
	if err != nil {
		return
	}
	result.Country = record.Country.IsoCode
	if len(record.City.Names) > 0 {
		result.City = record.City.Names["en"]
	}
	if len(record.Subdivisions) > 0 {
		result.Region = record.Subdivisions[0].IsoCode
	}
}

func (wp *WorkerPool) getASN(ip net.IP, result *ScanResult) {
	if wp.asnDB != nil {
		if rec, err := wp.asnDB.ASN(ip); err == nil && rec != nil && rec.AutonomousSystemNumber != 0 {
			result.ASN = fmt.Sprintf("AS%d %s", rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization)
			return
		}
	}
	if result.IsGenuineCFRange {
		result.ASN = "AS13335 Cloudflare, Inc."
	}
}

func (wp *WorkerPool) getReverseDNS(ip net.IP, result *ScanResult) {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return
	}
	result.Hostname = names[0]
}

func (wp *WorkerPool) detectDatacenter(result *ScanResult) {
	if result.CFRay != "" {
		if idx := strings.LastIndex(result.CFRay, "-"); idx >= 0 && idx+1 < len(result.CFRay) {
			code := result.CFRay[idx+1:]
			if len(code) >= 2 && len(code) <= 4 {
				result.Datacenter = strings.ToUpper(code)
			}
		}
	}

	switch {
	case result.HTTP3Supported:
		result.EdgeType = "h3"
	case result.HTTP2Supported:
		result.EdgeType = "h2"
	case result.HTTP11:
		result.EdgeType = "http/1.1"
	default:
		result.EdgeType = ""
	}
}

func (wp *WorkerPool) classifyOrigin(result *ScanResult) {
	ip := net.ParseIP(result.IP)
	result.IsGenuineCFRange = ip != nil && ipInRanges(ip, wp.cfRanges)

	type signal struct {
		present bool
		weight  int
	}
	issuer := strings.ToLower(result.CertIssuer)
	san := strings.ToLower(result.CertSAN)

	signals := []signal{
		{result.IsGenuineCFRange, 35}, 
		{result.CFRay != "", 15},
		{strings.EqualFold(result.ServerHeader, "cloudflare"), 15},
		{result.CFCacheStatus != "", 8},
		{result.CFRequestID != "", 5},
		{strings.Contains(issuer, "cloudflare") || strings.Contains(san, "cloudflare"), 12},
		{result.HTTP3Supported, 5},
		{result.HTTP2Supported, 5},
	}

	maxScore := 0
	got := 0
	for _, s := range signals {
		maxScore += s.weight
		if s.present {
			got += s.weight
		}
	}
	confidence := 0
	if maxScore > 0 {
		confidence = got * 100 / maxScore
	}
	result.CloudflareConfidence = confidence
	result.IsCloudflare = confidence >= 60

	looksLikeCF := result.CFRay != "" || strings.EqualFold(result.ServerHeader, "cloudflare") ||
		strings.Contains(issuer, "cloudflare")
	result.IsProxy = looksLikeCF && !result.IsGenuineCFRange
}

func (wp *WorkerPool) calculateScore(r *ScanResult) int {
	if !r.IsAlive {
		return 0
	}

	w := wp.config.ScoreWeights
	if (w == ScoreWeights{}) {
		w = defaultScoreWeights()
	}
	latencyRef := w.LatencyRefMs
	if latencyRef <= 0 {
		latencyRef = 300
	}
	speedRef := w.SpeedRefMBps
	if speedRef <= 0 {
		speedRef = 50
	}

	latencyScore := w.Latency
	switch {
	case r.TCPConnectMs <= 0:
		latencyScore = w.Latency * 0.5
	case r.TCPConnectMs >= latencyRef:
		latencyScore = 0
	default:
		latencyScore = w.Latency * (1 - r.TCPConnectMs/latencyRef)
	}

	reliabilityScore := w.Reliability * (1 - r.TCPFailureRate/100.0)
	if r.PacketLoss >= 0 {
		reliabilityScore = w.Reliability * (1 - (r.TCPFailureRate+r.PacketLoss)/200.0)
	}
	if reliabilityScore < 0 {
		reliabilityScore = 0
	}

	http3Score := 0.0
	if r.HTTP3Supported {
		http3Score = w.HTTP3
	}

	tlsScore := 0.0
	switch r.TLSVersion {
	case "TLS1.3":
		tlsScore = w.TLS
	case "TLS1.2":
		tlsScore = w.TLS * 0.5
	}

	speedScore := 0.0
	best := r.DownloadSpeed10MB
	if r.DownloadSpeed1MB > best {
		best = r.DownloadSpeed1MB
	}
	if best > 0 {
		speedScore = w.Speed * math.Min(best/speedRef, 1.0)
	}

	cfScore := float64(r.CloudflareConfidence) / 100.0 * w.Cloudflare

	total := latencyScore + reliabilityScore + http3Score + tlsScore + speedScore + cfScore
	max := w.Latency + w.Reliability + w.HTTP3 + w.TLS + w.Speed + w.Cloudflare
	if max <= 0 {
		max = 100
	}
	normalized := total / max * 100
	if normalized > 100 {
		normalized = 100
	}
	if normalized < 0 {
		normalized = 0
	}
	return int(math.Round(normalized))
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
		return "Unknown"
	}
}

func simpleTLSFingerprint(version uint16, cipher uint16, alpn string) string {
	raw := fmt.Sprintf("%d|%d|%s", version, cipher, alpn)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

var fallbackCFv4Ranges = []string{
	"103.21.24.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
	"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/17",
	"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
}

var fallbackCFv6Ranges = []string{
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2c0f:f248::/32",
	"2a06:98c0::/29",
}

func GetCloudflareRanges() []string {
	return []string{"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13"}
}

func GetAllCloudflareRanges() []string {
	return fallbackCFv4Ranges
}

func GetCloudflareIPv6Ranges() []string {
	return fallbackCFv6Ranges
}

func fetchOfficialCFRanges() []*net.IPNet {
	var cidrs []string
	client := &http.Client{Timeout: 10 * time.Second}

	for _, url := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				cidrs = append(cidrs, line)
			}
		}
	}

	if len(cidrs) == 0 {
		cidrs = append(cidrs, fallbackCFv4Ranges...)
		cidrs = append(cidrs, fallbackCFv6Ranges...)
	}

	return parseRangesToNets(cidrs)
}

func parseRangesToNets(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func ipInRanges(ip net.IP, ranges []*net.IPNet) bool {
	for _, n := range ranges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func addBigOffset(base net.IP, offset *big.Int) net.IP {
	baseInt := new(big.Int).SetBytes(base)
	sum := new(big.Int).Add(baseInt, offset)
	out := sum.Bytes()

	result := make(net.IP, len(base))
	if len(out) > len(result) {
		out = out[len(out)-len(result):]
	}
	copy(result[len(result)-len(out):], out)
	return result
}

func expandCIDR(cidr string, limit int, random bool) []net.IP {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	if limit <= 0 {
		limit = 10000
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones

	base := make(net.IP, len(network.IP))
	copy(base, network.IP.Mask(network.Mask))

	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	limitBig := big.NewInt(int64(limit))

	if !random || total.Cmp(limitBig) <= 0 {
		var ips []net.IP
		offset := big.NewInt(0)
		count := 0
		for offset.Cmp(total) < 0 && count < limit {
			ips = append(ips, addBigOffset(base, offset))
			offset = new(big.Int).Add(offset, big.NewInt(1))
			count++
		}
		return ips
	}

	return strideSample(base, total, limit)
}

func strideSample(base net.IP, total *big.Int, limit int) []net.IP {
	stride := new(big.Int).Div(total, big.NewInt(int64(limit)))
	if stride.Sign() == 0 {
		stride = big.NewInt(1)
	}

	ips := make([]net.IP, 0, limit)
	bucketStart := big.NewInt(0)

	for i := 0; i < limit; i++ {
		bucketEnd := new(big.Int).Add(bucketStart, stride)
		if bucketEnd.Cmp(total) > 0 {
			bucketEnd = total
		}
		width := new(big.Int).Sub(bucketEnd, bucketStart)
		if width.Sign() <= 0 {
			break
		}

		randOffset := randomBigInt(width)
		offset := new(big.Int).Add(bucketStart, randOffset)
		ips = append(ips, addBigOffset(base, offset))

		bucketStart = bucketEnd
		if bucketStart.Cmp(total) >= 0 {
			break
		}
	}
	return ips
}

func randomBigInt(max *big.Int) *big.Int {
	if max.Sign() <= 0 {
		return big.NewInt(0)
	}
	if max.IsInt64() && max.Int64() <= 1<<62 {
		return big.NewInt(rand.Int63n(max.Int64()))
	}
	bitLen := max.BitLen()
	byteLen := (bitLen + 7) / 8
	buf := make([]byte, byteLen)
	for {
		for i := range buf {
			buf[i] = byte(rand.Intn(256))
		}
		candidate := new(big.Int).SetBytes(buf)
		if candidate.Cmp(max) < 0 {
			return candidate
		}
	}
}

func expandRanges(ranges []string, limit int, random bool) []net.IP {
	var all []net.IP
	for _, cidr := range ranges {
		all = append(all, expandCIDR(cidr, limit, random)...)
	}
	return all
}

func collectFromSource(source string, cfg *ScanConfig) ([]net.IP, error) {
	limit := cfg.MaxIPsPerRange
	if limit <= 0 {
		limit = 10000
	}
	random := cfg.RandomSample

	switch {
	case source == "cloudflare":
		return expandRanges(GetCloudflareRanges(), limit, random), nil
	case source == "cloudflare_all":
		return expandRanges(GetAllCloudflareRanges(), limit, random), nil
	case source == "official":
		nets := fetchOfficialCFRanges()
		cidrs := make([]string, 0, len(nets))
		for _, n := range nets {
			cidrs = append(cidrs, n.String())
		}
		return expandRanges(cidrs, limit, random), nil
	case source == "asn13335":
		return expandRanges(GetCloudflareRanges(), limit, random), nil
	case source == "ipv6":
		return expandRanges(GetCloudflareIPv6Ranges(), limit, random), nil
	case source == "bgp":
		return collectBGPRanges(limit, random)
	case source == "custom", source == "historical":
		return nil, nil
	case strings.HasPrefix(source, "range:"):
		ranges := strings.Split(strings.TrimPrefix(source, "range:"), ",")
		return expandRanges(ranges, limit, random), nil
	case strings.HasPrefix(source, "custom:"):
		return collectCustomFile(strings.TrimPrefix(source, "custom:"))
	default:
		return collectCustomFile(source)
	}
}

func collectIPs(config *ScanConfig) ([]net.IP, error) {
	var allIPs []net.IP
	seen := make(map[string]bool)

	for _, source := range config.Sources {
		ips, err := collectFromSource(strings.TrimSpace(source), config)
		if err != nil {
			fmt.Printf("Warning: failed to collect from source %s: %v\n", source, err)
			continue
		}
		for _, ip := range ips {
			key := ip.String()
			if !seen[key] {
				seen[key] = true
				allIPs = append(allIPs, ip)
			}
		}
	}

	if config.ShuffleIPs {
		rand.Shuffle(len(allIPs), func(i, j int) {
			allIPs[i], allIPs[j] = allIPs[j], allIPs[i]
		})
	}

	return allIPs, nil
}

func collectBGPRanges(limit int, random bool) ([]net.IP, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Get("https://api.bgpview.io/asn/13335/prefixes")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Data struct {
			IPv4Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv4_prefixes"`
			IPv6Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var prefixes []string
	for _, p := range data.Data.IPv4Prefixes {
		prefixes = append(prefixes, p.Prefix)
	}
	for _, p := range data.Data.IPv6Prefixes {
		prefixes = append(prefixes, p.Prefix)
	}

	return expandRanges(prefixes, limit, random), nil
}

func collectCustomFile(filename string) ([]net.IP, error) {
	var ips []net.IP

	file, err := os.Open(filename)
	if err != nil {
		return ips, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			ips = append(ips, expandCIDR(line, 10000, false)...)
		} else if ip := net.ParseIP(line); ip != nil {
			ips = append(ips, ip)
		}
	}

	return ips, scanner.Err()
}

type resultWriter struct {
	format string
	file   *os.File
	mu     sync.Mutex

	csvWriter   *csv.Writer
	jsonStarted bool
}

func newResultWriter(config *ScanConfig) (*resultWriter, error) {
	file, err := os.Create(config.OutputPath)
	if err != nil {
		return nil, err
	}
	rw := &resultWriter{format: config.OutputFormat, file: file}

	switch rw.format {
	case "csv":
		rw.csvWriter = csv.NewWriter(file)
		header := csvHeader()
		if err := rw.csvWriter.Write(header); err != nil {
			file.Close()
			return nil, err
		}
		rw.csvWriter.Flush()
	case "json":
		if _, err := file.WriteString("[\n"); err != nil {
			file.Close()
			return nil, err
		}
	}

	return rw, nil
}

func (rw *resultWriter) Write(r ScanResult) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	switch rw.format {
	case "csv":
		if err := rw.csvWriter.Write(csvRow(r)); err != nil {
			return err
		}
		rw.csvWriter.Flush()
		return nil
	case "yaml":
		data, err := yaml.Marshal(r)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		for i, line := range lines {
			prefix := "  "
			if i == 0 {
				prefix = "- "
			}
			if _, err := rw.file.WriteString(prefix + line + "\n"); err != nil {
				return err
			}
		}
		return nil
	case "txt":
		if !r.IsAlive {
			return nil
		}
		_, err := fmt.Fprintf(rw.file, "%s:%d\n", r.IP, r.Port)
		return err
	default: 
		prefix := ",\n"
		if !rw.jsonStarted {
			prefix = ""
			rw.jsonStarted = true
		}
		data, err := json.MarshalIndent(r, "  ", "  ")
		if err != nil {
			return err
		}
		if _, err := rw.file.WriteString(prefix + "  " + string(data)); err != nil {
			return err
		}
		return nil
	}
}

func (rw *resultWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.format == "json" {
		rw.file.WriteString("\n]\n")
	}
	return rw.file.Close()
}

func csvHeader() []string {
	return []string{
		"ip", "port", "is_alive", "is_cloudflare", "cloudflare_confidence", "is_genuine_cf_range",
		"score", "source", "country", "city", "region", "asn", "hostname", "is_proxy",
		"datacenter", "edge_type", "tls_version", "tls_cipher", "tls_alpn", "tls_sni", "tls_fingerprint",
		"cert_issuer", "cert_san", "cert_expiry", "http_version",
		"http2_supported", "http3_supported", "cf_ray", "cf_cache_status",
		"server_header", "cf_request_id", "tcp_connect_ms", "tls_handshake_ms", "quic_handshake_ms",
		"ttfb_ms", "download_speed_1mb", "download_speed_10mb", "packet_loss", "tcp_failure_rate",
		"average_latency", "median_latency", "jitter", "http11", "scanned_at",
	}
}

func csvRow(r ScanResult) []string {
	return []string{
		r.IP, strconv.Itoa(r.Port), strconv.FormatBool(r.IsAlive),
		strconv.FormatBool(r.IsCloudflare), strconv.Itoa(r.CloudflareConfidence), strconv.FormatBool(r.IsGenuineCFRange),
		strconv.Itoa(r.Score), r.Source, r.Country, r.City, r.Region, r.ASN, r.Hostname,
		strconv.FormatBool(r.IsProxy), r.Datacenter, r.EdgeType, r.TLSVersion,
		r.TLSCipher, r.TLSALPN, r.TLSSNI, r.TLSFingerprint, r.CertIssuer, r.CertSAN,
		r.CertExpiry.Format(time.RFC3339), r.HTTPVersion,
		strconv.FormatBool(r.HTTP2Supported), strconv.FormatBool(r.HTTP3Supported),
		r.CFRay, r.CFCacheStatus, r.ServerHeader, r.CFRequestID,
		fmt.Sprintf("%.2f", r.TCPConnectMs), fmt.Sprintf("%.2f", r.TLSHandshakeMs), fmt.Sprintf("%.2f", r.QUICHandshakeMs),
		fmt.Sprintf("%.2f", r.TTFBMs), fmt.Sprintf("%.2f", r.DownloadSpeed1MB),
		fmt.Sprintf("%.2f", r.DownloadSpeed10MB), fmt.Sprintf("%.2f", r.PacketLoss), fmt.Sprintf("%.2f", r.TCPFailureRate),
		fmt.Sprintf("%.2f", r.AverageLatency), fmt.Sprintf("%.2f", r.MedianLatency),
		fmt.Sprintf("%.2f", r.Jitter), strconv.FormatBool(r.HTTP11),
		r.ScannedAt.Format(time.RFC3339),
	}
}

func writeTopResults(results []ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func loadGeoDB(path string) (*geoip2.Reader, error) {
	if path == "" {
		return nil, nil
	}
	return geoip2.Open(path)
}

func showHelp() {
	fmt.Println(`Cloudflare Scanner - Advanced IP Scanner

Usage:
  cf.exe [flags]

Flags:
  -source <source>         IP sources (comma-separated): cloudflare, cloudflare_all, official, bgp, asn13335, ipv6
                           or custom:filename.txt or range:cidr1,cidr2 (default: cloudflare)
                           "official" fetches Cloudflare's live published IP ranges.
  -workers <num>           Number of concurrent workers (default: 100)
  -ports <ports>           Ports to scan (comma-separated) (default: 443,80,2053,2083,2087,2096,8443)
  -domain <domain>         Test domain for validation (default: www.cloudflare.com)
  -speed-host <domain>     Host/SNI used only for the throughput sub-test (default: speed.cloudflare.com)
  -output <path>           Output file path (default: results.json); written incrementally, not buffered in RAM
  -format <format>         Output format: json, yaml, csv, txt (default: json)
  -geoip <path>            GeoIP City database path for location info
  -asn <path>              GeoIP ASN database path for ASN info
  -speed                   Enable real throughput test (downloads from /__down)
  -packet-loss             Enable real ICMP-based packet loss (needs raw/unprivileged ICMP socket permission)
  -no-http2                Disable HTTP/2 detection
  -no-http3                Disable HTTP/3 detection
  -no-rdns                 Disable reverse DNS lookup
  -no-save                 Disable saving live IPs to valid_ips_*.txt
  -random                  Sample IPs within each range via stride sampling instead of sequential scan
  -no-shuffle              Disable shuffling the overall scan order
  -latency-samples <num>   Steady-state RTT samples per IP used for jitter/failure-rate stats (default: 4)
  -stop-after <num>        Stop scanning once this many good results are found (0 = scan everything)
  -good-score <num>        Score threshold used by -stop-after (default: 70)
  -score-config <path>     YAML file overriding score weights (latency/reliability/http3/tls/speed/cloudflare)
  -timeout <seconds>       HTTP/TLS timeout in seconds (default: 5)
  -port-timeout <seconds>  Port scan timeout in seconds (default: 2)
  -rate <num>              Max new IP scans started per second (0 = unlimited)
  -max <num>               Maximum results to show / keep in the sorted top-results file (default: 20)
  -max-per-range <num>     Maximum IPs collected per CIDR range (default: 10000)
  -sort <sort>             Sort by: score, latency (applies to the top-results file; the main
                           output file is written in scan-completion order to keep memory bounded)
  -quiet                   Disable real-time output
  -noprogress              Disable progress display
  -nocolor                 Disable colors
  -help                    Show this help message

Examples:
  cf.exe -workers 200 -source cloudflare -output results.json
  cf.exe -source custom:ips.txt -ports 443,8443 -format csv -output scan.csv
  cf.exe -workers 300 -random -stop-after 20 -good-score 80
  cf.exe -source official,bgp -domain example.com -workers 300 -sort latency -speed -packet-loss`)
}

func defaultConfig() *ScanConfig {
	return &ScanConfig{
		Sources:            []string{"cloudflare"},
		WorkerCount:        100,
		Ports:              []int{443, 80, 2053, 2083, 2087, 2096, 8443},
		EnableHTTP2:        true,
		EnableHTTP3:        true,
		EnableSpeedTest:    false,
		EnablePacketLoss:   false,
		EnableGeoIP:        false,
		EnableReverseDNS:   true,
		OutputFormat:       "json",
		OutputPath:         "results.json",
		TestDomain:         "www.cloudflare.com",
		SpeedTestHost:      "speed.cloudflare.com",
		RateLimit:          1000,
		RealTimePrint:      true,
		ShowProgress:       true,
		MaxResults:         20,
		Timeout:            5,
		PortScanTimeout:    2,
		SortBy:             "score",
		NoColor:            false,
		MaxIPsPerRange:     10000,
		RandomSample:       false,
		ShuffleIPs:         true,
		LatencySamples:     4,
		SaveValidIPs:       true,
		StopAfterGood:      0,
		GoodScoreThreshold: 70,
		ScoreWeights:       defaultScoreWeights(),
	}
}

func parseArgs(args []string) (*ScanConfig, bool) {
	config := defaultConfig()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-help", "-h", "--help":
			return config, true
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
				var ports []int
				for _, p := range strings.Split(args[i+1], ",") {
					if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
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
		case "-speed-host":
			if i+1 < len(args) {
				config.SpeedTestHost = args[i+1]
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
		case "-asn":
			if i+1 < len(args) {
				config.ASNDBPath = args[i+1]
				i++
			}
		case "-speed":
			config.EnableSpeedTest = true
		case "-packet-loss":
			config.EnablePacketLoss = true
		case "-no-http2":
			config.EnableHTTP2 = false
		case "-no-http3":
			config.EnableHTTP3 = false
		case "-no-rdns":
			config.EnableReverseDNS = false
		case "-no-save":
			config.SaveValidIPs = false
		case "-random":
			config.RandomSample = true
		case "-no-shuffle":
			config.ShuffleIPs = false
		case "-latency-samples":
			if i+1 < len(args) {
				config.LatencySamples, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-stop-after":
			if i+1 < len(args) {
				config.StopAfterGood, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-good-score":
			if i+1 < len(args) {
				config.GoodScoreThreshold, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-score-config":
			if i+1 < len(args) {
				config.ScoreConfigPath = args[i+1]
				i++
			}
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
		case "-rate":
			if i+1 < len(args) {
				config.RateLimit, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-max":
			if i+1 < len(args) {
				config.MaxResults, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-max-per-range":
			if i+1 < len(args) {
				config.MaxIPsPerRange, _ = strconv.Atoi(args[i+1])
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

	return config, false
}

func main() {
	config, help := parseArgs(os.Args[1:])
	if help {
		showHelp()
		return
	}

	if err := RunScanner(config); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func RunScanner(config *ScanConfig) error {
	if config.ScoreConfigPath != "" {
		weights, err := loadScoreWeights(config.ScoreConfigPath)
		if err != nil {
			return fmt.Errorf("error loading score config: %v", err)
		}
		config.ScoreWeights = weights
	} else if (config.ScoreWeights == ScoreWeights{}) {
		config.ScoreWeights = defaultScoreWeights()
	}

	geoDB, _ := loadGeoDB(config.GeoIPDBPath)
	asnDB, _ := loadGeoDB(config.ASNDBPath)

	ips, err := collectIPs(config)
	if err != nil {
		return fmt.Errorf("error collecting IPs: %v", err)
	}

	fmt.Printf("Collected %d IPs to scan\n", len(ips))
	fmt.Printf("Using %d workers, scanning ports: %v\n", config.WorkerCount, config.Ports)
	fmt.Printf("Sort by: %s (applies to the top-results file only)\n", config.SortBy)
	fmt.Printf("Output will be streamed to: %s\n", config.OutputPath)
	fmt.Println("Scanning... (press Ctrl+C to stop)")
	fmt.Println()

	writer, err := newResultWriter(config)
	if err != nil {
		return fmt.Errorf("error creating output writer: %v", err)
	}

	pool := NewWorkerPool(config, geoDB, asnDB)
	pool.stats.Total = int64(len(ips))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		if _, ok := <-sigCh; ok {
			fmt.Println("\nStopping scan, finishing up...")
			pool.cancel()
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()

	var wg sync.WaitGroup
	pool.Start(&wg)

	var collector sync.WaitGroup
	collector.Add(1)
	go func() {
		defer collector.Done()
		for result := range pool.results {
			if err := writer.Write(result); err != nil {
				fmt.Printf("Warning: failed to write result for %s: %v\n", result.IP, err)
			}
		}
	}()

dispatch:
	for _, ip := range ips {
		select {
		case pool.jobs <- ip:
		case <-pool.ctx.Done():
			break dispatch
		}
	}

	close(pool.jobs)
	wg.Wait()
	close(pool.results)
	collector.Wait()

	if err := writer.Close(); err != nil {
		return fmt.Errorf("error finalizing output: %v", err)
	}

	pool.cancel()
	pool.limiter.Close()

	if pool.validFile != nil {
		pool.validFile.Close()
		fmt.Printf("\nValid IPs saved to: %s\n", pool.validFile.Name())
	}

	total, scanned, alive, dead, http3, best := pool.stats.Snapshot()
	fmt.Printf("\n\nScan Complete!\n")
	fmt.Printf("Total: %d | Scanned: %d | Alive: %d | Dead: %d | HTTP3: %d | Best: %.2fms | Time: %s\n",
		total, scanned, alive, dead, http3, best, time.Since(pool.startTime).Round(time.Second))

	pool.topMu.Lock()
	top := make([]ScanResult, len(pool.topResults))
	copy(top, pool.topResults)
	pool.topMu.Unlock()

	topPath := topResultsPath(config.OutputPath)
	if err := writeTopResults(top, topPath); err != nil {
		fmt.Printf("Warning: failed to write sorted top-results file: %v\n", err)
	} else {
		fmt.Printf("Full results streamed to: %s\n", config.OutputPath)
		fmt.Printf("Sorted top %d results saved to: %s\n", len(top), topPath)
	}

	fmt.Printf("\nTop %d results:\n", config.MaxResults)
	for i, r := range top {
		cf, h2, h3 := "✗", "✗", "✗"
		if r.IsCloudflare {
			cf = "✓"
		}
		if r.HTTP2Supported {
			h2 = "✓"
		}
		if r.HTTP3Supported {
			h3 = "✓"
		}
		fmt.Printf("%-15s Score:%3d Lat:%7.2fms CF:%s(%d%%) H2:%s H3:%s Ray:%s\n",
			r.IP, r.Score, r.TCPConnectMs, cf, r.CloudflareConfidence, h2, h3, r.CFRay)
		if i+1 >= config.MaxResults {
			break
		}
	}

	return nil
}

func topResultsPath(outputPath string) string {
	ext := ""
	base := outputPath
	if idx := strings.LastIndex(outputPath, "."); idx > 0 {
		ext = outputPath[idx:]
		base = outputPath[:idx]
	}
	return base + "_top" + ext
}

func EstimateScanTime(ranges []string, workers int, ports []int, maxIPsPerRange int) (string, string) {
	if workers <= 0 {
		workers = 1
	}
	if len(ports) == 0 {
		ports = []int{443}
	}
	if maxIPsPerRange <= 0 {
		maxIPsPerRange = 10000
	}

	var totalTargets int64
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		totalIPs := int64(1) << uint(bits-ones)
		if totalIPs < int64(maxIPsPerRange) {
			totalTargets += totalIPs
		} else {
			totalTargets += int64(maxIPsPerRange)
		}
	}

	const avgPerCheck = 0.02

	seconds := float64(totalTargets) * avgPerCheck / float64(workers)

	var text, color string
	switch {
	case seconds < 60:
		text = fmt.Sprintf("%.0f sec", seconds)
		color = Green
	case seconds < 600:
		text = fmt.Sprintf("%.1f min", seconds/60)
		color = Green
	case seconds < 3600:
		text = fmt.Sprintf("%.1f min", seconds/60)
		color = Yellow
	case seconds < 7200:
		text = fmt.Sprintf("%.1f hr", seconds/3600)
		color = Yellow
	default:
		text = fmt.Sprintf("%.1f hr", seconds/3600)
		color = Red
	}

	return text, color
}
