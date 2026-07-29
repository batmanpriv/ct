package cf

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"math"
	
	"github.com/oschwald/geoip2-golang"
	"github.com/quic-go/quic-go"
	"gopkg.in/yaml.v3"
	"github.com/quic-go/quic-go/http3"
)

const (
	CloudflareASN  = 13335
	BufferSize     = 10000
	RequestTimeout = 10 * time.Second
)

type ScanResult struct {
	IP                string    `json:"ip" yaml:"ip" csv:"ip"`
	Port              int       `json:"port" yaml:"port" csv:"port"`
	IsAlive           bool      `json:"is_alive" yaml:"is_alive" csv:"is_alive"`
	IsCloudflare      bool      `json:"is_cloudflare" yaml:"is_cloudflare" csv:"is_cloudflare"`
	Score             int       `json:"score" yaml:"score" csv:"score"`
	Source            string    `json:"source" yaml:"source" csv:"source"`
	Country           string    `json:"country" yaml:"country" csv:"country"`
	City              string    `json:"city" yaml:"city" csv:"city"`
	Region            string    `json:"region" yaml:"region" csv:"region"`
	ASN               string    `json:"asn" yaml:"asn" csv:"asn"`
	Hostname          string    `json:"hostname" yaml:"hostname" csv:"hostname"`
	IsProxy           bool      `json:"is_proxy" yaml:"is_proxy" csv:"is_proxy"`
	EdgeType          string    `json:"edge_type" yaml:"edge_type" csv:"edge_type"`
	TLSVersion        string    `json:"tls_version" yaml:"tls_version" csv:"tls_version"`
	TLSCipher         string    `json:"tls_cipher" yaml:"tls_cipher" csv:"tls_cipher"`
	TLSALPN           string    `json:"tls_alpn" yaml:"tls_alpn" csv:"tls_alpn"`
	TLSSNI            string    `json:"tls_sni" yaml:"tls_sni" csv:"tls_sni"`
	CertIssuer        string    `json:"cert_issuer" yaml:"cert_issuer" csv:"cert_issuer"`
	CertSAN           string    `json:"cert_san" yaml:"cert_san" csv:"cert_san"`
	CertExpiry        time.Time `json:"cert_expiry" yaml:"cert_expiry" csv:"cert_expiry"`
	HTTPVersion       string    `json:"http_version" yaml:"http_version" csv:"http_version"`
	HTTP2Supported    bool      `json:"http2_supported" yaml:"http2_supported" csv:"http2_supported"`
	HTTP3Supported    bool      `json:"http3_supported" yaml:"http3_supported" csv:"http3_supported"`
	CFRay             string    `json:"cf_ray" yaml:"cf_ray" csv:"cf_ray"`
	CFCacheStatus     string    `json:"cf_cache_status" yaml:"cf_cache_status" csv:"cf_cache_status"`
	ServerHeader      string    `json:"server_header" yaml:"server_header" csv:"server_header"`
	CFRequestID       string    `json:"cf_request_id" yaml:"cf_request_id" csv:"cf_request_id"`
	TCPConnectMs      float64   `json:"tcp_connect_ms" yaml:"tcp_connect_ms" csv:"tcp_connect_ms"`
	TLSHandshakeMs    float64   `json:"tls_handshake_ms" yaml:"tls_handshake_ms" csv:"tls_handshake_ms"`
	TTFBMs            float64   `json:"ttfb_ms" yaml:"ttfb_ms" csv:"ttfb_ms"`
	DownloadMs        float64   `json:"download_ms" yaml:"download_ms" csv:"download_ms"`
	KeepAliveMs       float64   `json:"keep_alive_ms" yaml:"keep_alive_ms" csv:"keep_alive_ms"`
	DownloadSpeed1MB  float64   `json:"download_speed_1mb" yaml:"download_speed_1mb" csv:"download_speed_1mb"`
	DownloadSpeed10MB float64   `json:"download_speed_10mb" yaml:"download_speed_10mb" csv:"download_speed_10mb"`
	PacketLoss        float64   `json:"packet_loss" yaml:"packet_loss" csv:"packet_loss"`
	AverageLatency    float64   `json:"average_latency" yaml:"average_latency" csv:"average_latency"`
	MedianLatency     float64   `json:"median_latency" yaml:"median_latency" csv:"median_latency"`
	Jitter            float64   `json:"jitter" yaml:"jitter" csv:"jitter"`
	Ports             []int     `json:"ports" yaml:"ports" csv:"ports"`
	HTTP11            bool      `json:"http11" yaml:"http11" csv:"http11"`
	ScannedAt         time.Time `json:"scanned_at" yaml:"scanned_at" csv:"scanned_at"`
}

type ScanConfig struct {
	Sources          []string
	WorkerCount      int
	Ports            []int
	EnableHTTP2      bool
	EnableHTTP3      bool
	EnableSpeedTest  bool
	EnableGeoIP      bool
	EnableReverseDNS bool
	EnableBenchmark  bool
	GeoIPDBPath      string
	OutputFormat     string
	OutputPath       string
	ResumeDBPath     string
	TestDomain       string
	RateLimit        int
	RealTimePrint    bool
	ShowProgress     bool
	MaxResults       int
	Timeout          int
	PortScanTimeout  int
	SortBy           string
	NoColor          bool
	MaxIPsPerRange   int 
}

type WorkerPool struct {
	workers     int
	jobs        chan net.IP
	results     chan ScanResult
	ctx         context.Context
	cancel      context.CancelFunc
	config      *ScanConfig
	geoDB       *geoip2.Reader
	mu          sync.Mutex
	scanned     map[string]bool
	stats       *ScanStats
	printMu     sync.Mutex
	startTime   time.Time
	topResults  []ScanResult
	topMu       sync.Mutex
	validFile   *os.File
	validMu     sync.Mutex
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

func NewWorkerPool(config *ScanConfig, geoDB *geoip2.Reader) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	timestamp := time.Now().Format("20060102_150405")
	validFileName := fmt.Sprintf("valid_ips_%s.txt", timestamp)
	validFile, _ := os.OpenFile(validFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

	return &WorkerPool{
		workers:    config.WorkerCount,
		jobs:       make(chan net.IP, BufferSize),
		results:    make(chan ScanResult, BufferSize),
		ctx:        ctx,
		cancel:     cancel,
		config:     config,
		geoDB:      geoDB,
		scanned:    make(map[string]bool),
		stats:      &ScanStats{},
		startTime:  time.Now(),
		topResults: make([]ScanResult, 0, config.MaxResults),
		validFile:  validFile,
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
			result := wp.scanIP(ip)
			wp.results <- result
			wp.updateStats(result)

			if result.IsAlive {
				wp.saveValidIP(result)
				wp.updateTopResults(result)
				if wp.config.RealTimePrint {
					wp.printTopResults()
				}
			}

			if wp.config.ShowProgress && wp.stats.Scanned%50 == 0 {
				wp.printProgress()
			}
		}
	}
}

func (wp *WorkerPool) saveValidIP(result ScanResult) {
	wp.validMu.Lock()
	defer wp.validMu.Unlock()

	if wp.validFile != nil {
		line := fmt.Sprintf("%s:%d\n", result.IP, result.Port)
		wp.validFile.WriteString(line)
		wp.validFile.Sync()
	}
}

func (wp *WorkerPool) updateTopResults(result ScanResult) {
	wp.topMu.Lock()
	defer wp.topMu.Unlock()

	for i, r := range wp.topResults {
		if r.IP == result.IP && r.Port == result.Port {
			wp.topResults[i] = result
			wp.sortTopResults()
			return
		}
	}

	wp.topResults = append(wp.topResults, result)
	wp.sortTopResults()

	if len(wp.topResults) > wp.config.MaxResults {
		wp.topResults = wp.topResults[:wp.config.MaxResults]
	}
}

func (wp *WorkerPool) sortTopResults() {
	sort.Slice(wp.topResults, func(i, j int) bool {
		if wp.config.SortBy == "latency" {
			if wp.topResults[i].TCPConnectMs != wp.topResults[j].TCPConnectMs {
				return wp.topResults[i].TCPConnectMs < wp.topResults[j].TCPConnectMs
			}
			return wp.topResults[i].Score > wp.topResults[j].Score
		}
		if wp.topResults[i].Score != wp.topResults[j].Score {
			return wp.topResults[i].Score > wp.topResults[j].Score
		}
		return wp.topResults[i].TCPConnectMs < wp.topResults[j].TCPConnectMs
	})
}

func (wp *WorkerPool) printTopResults() {
	wp.printMu.Lock()
	defer wp.printMu.Unlock()

	wp.topMu.Lock()
	top := make([]ScanResult, len(wp.topResults))
	copy(top, wp.topResults)
	wp.topMu.Unlock()

	fmt.Print("\033[H\033[2J")

	red := Red
	green := Green
	yellow := Yellow
	blue := Blue
	cyan := Cyan
	white := White
	magenta := Magenta
	reset := Reset
	
	if wp.config.NoColor {
		red, green, yellow, blue, cyan, white, magenta, reset = "", "", "", "", "", "", "", ""
	}

	fmt.Printf("%s╔════════════════════════════════════════════════════════════════════════════%s╗%s\n", cyan, cyan, reset)
	fmt.Printf("%s║                     %sCloudflare Scanner - Top %d Valid IPs%s                  %s║%s\n", 
		cyan, yellow, wp.config.MaxResults, reset, cyan, reset)
	fmt.Printf("%s╠════════════════════════════════════════════════════════════════════════════%s╣%s\n", cyan, cyan, reset)

	elapsed := time.Since(wp.startTime)
	percent := float64(wp.stats.Scanned) / float64(wp.stats.Total) * 100
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
		green, reset, green, wp.stats.Alive, reset,
		red, reset, red, wp.stats.Dead, reset,
		blue, reset, blue, wp.stats.HTTP3, reset,
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

			cfColor := red
			cfText := "✗"
			if r.IsCloudflare {
				cfColor = green
				cfText = "✓"
			}

			h2Color := red
			h2Text := "✗"
			if r.HTTP2Supported {
				h2Color = green
				h2Text = "✓"
			}

			h3Color := red
			h3Text := "✗"
			if r.HTTP3Supported {
				h3Color = green
				h3Text = "✓"
			}

			latColor := green
			if r.TCPConnectMs > 300 {
				latColor = red
			} else if r.TCPConnectMs > 150 {
				latColor = yellow
			}

			fmt.Printf("%s║ %s#%-2d%s %s%-15s%s %s:%-5d%s %sScore:%s%3d%s  %sLat:%s%7.2fms%s  %sCF:%s%s%s %sH2:%s%s%s %sH3:%s%s%s        %s║%s\n",
				cyan, 
				magenta, i+1, reset,
				green, r.IP, reset,
				yellow, r.Port, reset,
				white, scoreColor, r.Score, reset,
				white, latColor, r.TCPConnectMs, reset,
				white, cfColor, cfText, reset,
				white, h2Color, h2Text, reset,
				white, h3Color, h3Text, reset, 
				cyan, reset)
		}
	}

	fmt.Printf("%s╚════════════════════════════════════════════════════════════════════════════%s╝%s\n", cyan, cyan, reset)
	
	fmt.Printf("%sTotal Scanned:%s %s%d%s  |  %sValid saved to:%s %svalid_ips_*.txt%s\n",
		cyan, reset,
		green, wp.stats.Scanned, reset,
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
	wp.stats.mu.Lock()
	scanned := wp.stats.Scanned
	total := wp.stats.Total
	wp.stats.mu.Unlock()

	if scanned == 0 {
		return 0
	}

	elapsed := time.Since(wp.startTime)
	rate := float64(scanned) / elapsed.Seconds()

	if rate <= 0 {
		return 0
	}

	remain := float64(total - scanned)
	return time.Duration(remain/rate) * time.Second
}

func (wp *WorkerPool) printProgress() {
	wp.printMu.Lock()
	defer wp.printMu.Unlock()

	elapsed := time.Since(wp.startTime)
	percent := float64(wp.stats.Scanned) / float64(wp.stats.Total) * 100
	eta := wp.estimateETA()
	etaStr := eta.Round(time.Second).String()
	if eta == 0 {
		etaStr = "calculating"
	}

	fmt.Printf("\r[%d/%d] %.1f%%  Alive:%d  Dead:%d  H3:%d  ETA:%s  Elapsed:%s",
		wp.stats.Scanned, wp.stats.Total, percent,
		wp.stats.Alive, wp.stats.Dead, wp.stats.HTTP3,
		etaStr, elapsed.Round(time.Second))
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

	wp.mu.Lock()
	if wp.scanned[result.IP] {
		wp.mu.Unlock()
		return result
	}
	wp.scanned[result.IP] = true
	wp.mu.Unlock()

	ports := wp.config.Ports
	if len(ports) == 0 {
		ports = []int{443}
	}

	bestLatency := math.MaxFloat64

	for _, port := range ports {

		tmp := ScanResult{}

		if !wp.scanPort(ip, port, &tmp) {
			continue
		}

		result.IsAlive = true
		result.Ports = append(result.Ports, port)

		if tmp.TCPConnectMs < bestLatency {
			bestLatency = tmp.TCPConnectMs
			result.Port = port
			result.TCPConnectMs = tmp.TCPConnectMs
		}
	}

	if !result.IsAlive {
		return result
	}

	wp.gatherTLSInfo(ip, result.Port, &result)
	wp.gatherHTTPInfo(ip, result.Port, &result)

	if wp.config.EnableHTTP2 {
		wp.testHTTP2(ip, result.Port, &result)
	}

	if wp.config.EnableHTTP3 {
		wp.testHTTP3(ip, result.Port, &result)
	}

	wp.measureLatency(ip, result.Port, &result)
	wp.testPacketLoss(ip, result.Port, &result)

	if wp.config.EnableSpeedTest {
		wp.testSpeed(ip, result.Port, &result)
	}

	if wp.config.EnableGeoIP && wp.geoDB != nil {
		wp.getGeoIP(ip, &result)
	}

	if wp.config.EnableReverseDNS {
		wp.getReverseDNS(ip, &result)
	}

	wp.detectEdgeType(&result)
	wp.detectProxy(&result)

	result.IsCloudflare = wp.validateCloudflare(&result)

	result.Score = wp.calculateScore(&result)

	return result
}

func (wp *WorkerPool) scanPort(ip net.IP, port int, result *ScanResult) bool {
	timeout := time.Duration(wp.config.PortScanTimeout) * time.Second
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	result.TCPConnectMs = float64(time.Since(start).Microseconds()) / 1000
	result.IsAlive = true
	return true
}

func (wp *WorkerPool) validateCloudflare(result *ScanResult) bool {
	score := 0

	if result.CFRay != "" {
		score += 4
	}

	if result.CFCacheStatus != "" {
		score += 3
	}

	if result.CFRequestID != "" {
		score += 2
	}

	if strings.EqualFold(result.ServerHeader, "cloudflare") {
		score += 3
	}

	issuer := strings.ToLower(result.CertIssuer)
	san := strings.ToLower(result.CertSAN)

	if strings.Contains(issuer, "cloudflare") {
		score += 2
	}

	if strings.Contains(san, "cloudflare") {
		score += 2
	}

	if result.HTTP2Supported {
		score++
	}

	if result.HTTP3Supported {
		score++
	}

	if result.EdgeType != "" {
		score++
	}

	return score >= 5
}

func (wp *WorkerPool) gatherTLSInfo(ip net.IP, port int, result *ScanResult) {
	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	rawConn, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort(ip.String(), strconv.Itoa(port)),
		timeout,
	)
	if err != nil {
		return
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         wp.config.TestDomain,
		InsecureSkipVerify: true,
		NextProtos: []string{
			"h2",
			"http/1.1",
		},
	})

	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}

	result.TLSHandshakeMs =
		float64(time.Since(start).Microseconds()) / 1000

	state := tlsConn.ConnectionState()

	result.TLSVersion = tlsVersionString(state.Version)
	result.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
	result.TLSALPN = state.NegotiatedProtocol
	result.TLSSNI = wp.config.TestDomain

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertIssuer = cert.Issuer.CommonName
		result.CertSAN = strings.Join(cert.DNSNames, ",")
		result.CertExpiry = cert.NotAfter
	}
}

func (wp *WorkerPool) gatherHTTPInfo(ip net.IP, port int, result *ScanResult) {
	if port == 0 {
		port = 443
	}

	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout == 0 {
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
			d := &net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, network, targetAddr)
		},

		DisableCompression: true,
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(
		"HEAD",
		"https://"+wp.config.TestDomain+"/",
		nil,
	)
	if err != nil {
		return
	}

	req.Host = wp.config.TestDomain

	req.Header.Set("User-Agent", "CloudflareScanner/2.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	result.TTFBMs = float64(time.Since(start).Microseconds()) / 1000.0

	result.HTTPVersion = resp.Proto

	result.ServerHeader = resp.Header.Get("Server")
	result.CFRay = resp.Header.Get("CF-Ray")
	result.CFCacheStatus = resp.Header.Get("CF-Cache-Status")
	result.CFRequestID = resp.Header.Get("CF-Request-ID")

	if resp.ProtoMajor == 2 {
		result.HTTP2Supported = true
	}

	if strings.Contains(strings.ToLower(resp.Header.Get("Alt-Svc")), "h3") {
		result.HTTP3Supported = true
	}

	if strings.EqualFold(result.ServerHeader, "cloudflare") ||
		result.CFRay != "" ||
		result.CFCacheStatus != "" {

		result.IsCloudflare = true
	}
}

func (wp *WorkerPool) testHTTP2(ip net.IP, port int, result *ScanResult) {
	if port == 0 {
		port = 443
	}

	tlsConfig := &tls.Config{
		ServerName:         wp.config.TestDomain,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), tlsConfig)
	if err != nil {
		return
	}
	defer conn.Close()

	if err := conn.HandshakeContext(context.Background()); err != nil {
		return
	}

	state := conn.ConnectionState()
	result.HTTP2Supported = state.NegotiatedProtocol == "h2"
	result.HTTP11 = state.NegotiatedProtocol == "http/1.1"
}

func (wp *WorkerPool) testHTTP3(ip net.IP, port int, result *ScanResult) {
	if port == 0 {
		port = 443
	}

	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         wp.config.TestDomain,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},

		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, target, tlsConf, cfg)
		},
	}
	defer tr.Close()

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequest(
		http.MethodHead,
		"https://"+wp.config.TestDomain+"/",
		nil,
	)
	if err != nil {
		return
	}

	req.Host = wp.config.TestDomain
	req.Header.Set("User-Agent", "CloudflareScanner/3.0")

	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	result.HTTP3Supported = true
	result.TTFBMs = float64(time.Since(start).Microseconds()) / 1000

	result.HTTPVersion = resp.Proto

	if ray := resp.Header.Get("CF-Ray"); ray != "" {
		result.CFRay = ray
	}

	if cache := resp.Header.Get("CF-Cache-Status"); cache != "" {
		result.CFCacheStatus = cache
	}

	if server := resp.Header.Get("Server"); server != "" {
		result.ServerHeader = server
	}

	if rid := resp.Header.Get("CF-Request-ID"); rid != "" {
		result.CFRequestID = rid
	}
}

func (wp *WorkerPool) measureLatency(ip net.IP, port int, result *ScanResult) {
	const samples = 5

	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	targetAddr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	var latencies []float64

	for i := 0; i < samples; i++ {

		transport := &http.Transport{
			ForceAttemptHTTP2: true,
			DisableKeepAlives: true,

			TLSClientConfig: &tls.Config{
				ServerName:         wp.config.TestDomain,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
			},

			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{
					Timeout: timeout,
				}
				return d.DialContext(ctx, network, targetAddr)
			},
		}

		client := &http.Client{
			Timeout:   timeout,
			Transport: transport,
		}

		req, err := http.NewRequest(
			http.MethodHead,
			"https://"+wp.config.TestDomain+"/",
			nil,
		)
		if err != nil {
			continue
		}

		req.Host = wp.config.TestDomain

		start := time.Now()

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		latencies = append(
			latencies,
			float64(time.Since(start).Microseconds())/1000.0,
		)

		time.Sleep(100 * time.Millisecond)
	}

	if len(latencies) == 0 {
		return
	}

	sort.Float64s(latencies)

	var sum float64
	for _, v := range latencies {
		sum += v
	}

	avg := sum / float64(len(latencies))
	result.AverageLatency = avg

	if len(latencies)%2 == 0 {
		result.MedianLatency =
			(latencies[len(latencies)/2-1] + latencies[len(latencies)/2]) / 2
	} else {
		result.MedianLatency = latencies[len(latencies)/2]
	}

	var variance float64
	for _, v := range latencies {
		diff := v - avg
		variance += diff * diff
	}

	variance /= float64(len(latencies))
	result.Jitter = math.Sqrt(variance)
}

func (wp *WorkerPool) testPacketLoss(ip net.IP, port int, result *ScanResult) {
	total := 5
	success := 0

	timeout := time.Duration(wp.config.PortScanTimeout) * time.Second
	if timeout == 0 {
		timeout = 1 * time.Second
	}

	for i := 0; i < total; i++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout)
		if err == nil {
			success++
			conn.Close()
		}
	}

	result.PacketLoss = float64(total-success) / float64(total) * 100
}

func (wp *WorkerPool) testSpeed(ip net.IP, port int, result *ScanResult) {
	timeout := time.Duration(wp.config.Timeout) * time.Second
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}

	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			ServerName:         wp.config.TestDomain,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, network, target)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	tests := []struct {
		SizeMB int
		Field  *float64
	}{
		{1, &result.DownloadSpeed1MB},
		{10, &result.DownloadSpeed10MB},
	}

	for _, t := range tests {

		url := fmt.Sprintf(
			"https://%s/cdn-cgi/trace?speed=%d",
			wp.config.TestDomain,
			t.SizeMB,
		)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		req.Host = wp.config.TestDomain
		req.Header.Set("User-Agent", "CloudflareScanner/3.0")
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

		buf := make([]byte, 64*1024)

		var downloaded int64

		for {

			n, err := resp.Body.Read(buf)

			if n > 0 {
				downloaded += int64(n)
			}

			if err == io.EOF {
				break
			}

			if err != nil {
				resp.Body.Close()
				downloaded = 0
				break
			}
		}

		resp.Body.Close()

		if downloaded == 0 {
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

func (wp *WorkerPool) getReverseDNS(ip net.IP, result *ScanResult) {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return
	}

	if len(names) > 0 {
		result.Hostname = names[0]
	}
}

func (wp *WorkerPool) detectEdgeType(result *ScanResult) {
	if result.CFRay != "" {
		if strings.Contains(result.CFRay, "-") {
			parts := strings.Split(result.CFRay, "-")
			if len(parts) > 1 {
				switch {
				case strings.Contains(parts[1], "worker"):
					result.EdgeType = "Worker"
				case strings.Contains(parts[1], "cache"):
					result.EdgeType = "Cache"
				case strings.Contains(parts[1], "spectrum"):
					result.EdgeType = "Spectrum"
				case strings.Contains(parts[1], "tunnel"):
					result.EdgeType = "Tunnel"
				default:
					result.EdgeType = "CDN"
				}
			}
		}
	}

	if result.EdgeType == "" {
		result.EdgeType = "CDN"
	}
}

func (wp *WorkerPool) detectProxy(result *ScanResult) {
	proxyIndicators := []string{
		"proxy", "forward", "gateway", "cache",
	}

	for _, indicator := range proxyIndicators {
		if strings.Contains(strings.ToLower(result.Hostname), indicator) {
			result.IsProxy = true
			return
		}
	}

	if result.ServerHeader != "" && strings.Contains(strings.ToLower(result.ServerHeader), "proxy") {
		result.IsProxy = true
	}
}

func (wp *WorkerPool) calculateScore(r *ScanResult) int {

	score := 0

	if !r.IsAlive {
		return 0
	}

	score += 10

	if r.IsCloudflare {
		score += 25
	}

	if r.HTTP2Supported {
		score += 10
	}

	if r.HTTP3Supported {
		score += 15
	}

	switch {

	case r.TCPConnectMs < 30:
		score += 20

	case r.TCPConnectMs < 60:
		score += 15

	case r.TCPConnectMs < 100:
		score += 10

	case r.TCPConnectMs < 200:
		score += 5
	}

	switch {

	case r.PacketLoss == 0:
		score += 10

	case r.PacketLoss < 2:
		score += 8

	case r.PacketLoss < 5:
		score += 5
	}

	if r.DownloadSpeed10MB > 30 {
		score += 10
	} else if r.DownloadSpeed1MB > 10 {
		score += 5
	}

	if score > 100 {
		score = 100
	}

	return score
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

func collectCloudflareIPsWithRangesAndLimit(customRanges []string, maxPerRange int) ([]net.IP, error) {
	if maxPerRange <= 0 {
		maxPerRange = 10000
	}

	var ips []net.IP
	ranges := customRanges
	
	if len(ranges) == 0 {
		ranges = GetCloudflareRanges()
	}
	
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		
		ip := network.IP.Mask(network.Mask)
		count := 0
		for network.Contains(ip) && count < maxPerRange {
			ips = append(ips, net.ParseIP(ip.String()))
			incrementIP(ip)
			count++
		}
	}
	
	return ips, nil
}

func collectIPs(config *ScanConfig) ([]net.IP, error) {
	var allIPs []net.IP
	seen := make(map[string]bool)

	maxPerRange := config.MaxIPsPerRange
	if maxPerRange <= 0 {
		maxPerRange = 10000
	}

	for _, source := range config.Sources {
		var ips []net.IP
		var err error
		
		if strings.HasPrefix(source, "range:") {
			ranges := strings.Split(strings.TrimPrefix(source, "range:"), ",")
			ips, err = collectCloudflareIPsWithRangesAndLimit(ranges, maxPerRange)
		} else {
			ips, err = collectFromSourceWithLimit(source, maxPerRange)
		}
		
		if err != nil {
			fmt.Printf("Warning: Failed to collect from source %s: %v\n", source, err)
			continue
		}

		for _, ip := range ips {
			if !seen[ip.String()] {
				seen[ip.String()] = true
				allIPs = append(allIPs, ip)
			}
		}
	}

	return allIPs, nil
}

func collectFromSource(source string) ([]net.IP, error) {
	switch source {
	case "cloudflare":
		return collectCloudflareIPs()
	case "cloudflare_all":
		allRanges := GetAllCloudflareRanges()
		var ips []net.IP
		for _, cidr := range allRanges {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ip := network.IP.Mask(network.Mask)
			count := 0
			for network.Contains(ip) && count < 10000 {
				ips = append(ips, net.ParseIP(ip.String()))
				incrementIP(ip)
				count++
			}
		}
		return ips, nil
	case "bgp":
		return collectBGPRanges()
	case "asn13335":
		return collectASNRange()
	case "custom":
		return collectCustomIPs()
	case "historical":
		return collectHistoricalIPs()
	case "ipv6":
		return collectIPv6Range()
	default:
		if strings.HasPrefix(source, "custom:") {
			return collectCustomFile(strings.TrimPrefix(source, "custom:"))
		}
		return collectCustomFile(source)
	}
}

func GetCloudflareRanges() []string {
	return []string{
		"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
	}
}

func GetAllCloudflareRanges() []string {
	return []string{
		"103.21.24.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
		"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/17",
		"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
		"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
		"2405:b500::/32", "2405:8100::/32", "2c0f:f248::/32",
		"2a06:98c0::/29",
	}
}

func collectCloudflareIPsWithLimit(maxPerRange int) ([]net.IP, error) {
	var ips []net.IP
	if maxPerRange <= 0 {
		maxPerRange = 10000
	}

	for _, cidr := range GetCloudflareRanges() {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ip := make(net.IP, len(network.IP))
		copy(ip, network.IP.Mask(network.Mask))

		count := 0
		for network.Contains(ip) && count < maxPerRange {
			tmp := make(net.IP, len(ip))
			copy(tmp, ip)
			ips = append(ips, tmp)
			incrementIP(ip)
			count++
		}
	}

	return ips, nil
}

func collectCloudflareIPs() ([]net.IP, error) {
	var ips []net.IP
	maxPerRange := 10000
	
	for _, cidr := range GetCloudflareRanges() {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ip := make(net.IP, len(network.IP))
		copy(ip, network.IP.Mask(network.Mask))

		count := 0
		for network.Contains(ip) && count < maxPerRange {
			tmp := make(net.IP, len(ip))
			copy(tmp, ip)
			ips = append(ips, tmp)
			incrementIP(ip)
			count++
		}
	}

	return ips, nil
}

func collectFromSourceWithLimit(source string, maxPerRange int) ([]net.IP, error) {
	if maxPerRange <= 0 {
		maxPerRange = 10000
	}

	switch source {
	case "cloudflare":
		return collectCloudflareIPsWithLimit(maxPerRange)
	case "cloudflare_all":
		allRanges := GetAllCloudflareRanges()
		var ips []net.IP
		for _, cidr := range allRanges {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ip := network.IP.Mask(network.Mask)
			count := 0
			for network.Contains(ip) && count < maxPerRange {
				ips = append(ips, net.ParseIP(ip.String()))
				incrementIP(ip)
				count++
			}
		}
		return ips, nil
	case "bgp":
		return collectBGPRangesWithLimit(maxPerRange)
	case "asn13335":
		return collectCloudflareIPsWithLimit(maxPerRange)
	case "custom":
		return collectCustomIPs()
	case "historical":
		return collectHistoricalIPs()
	case "ipv6":
		return collectIPv6Range()
	default:
		if strings.HasPrefix(source, "custom:") {
			return collectCustomFile(strings.TrimPrefix(source, "custom:"))
		}
		return collectCustomFile(source)
	}
}

func collectBGPRangesWithLimit(maxPerRange int) ([]net.IP, error) {
	if maxPerRange <= 0 {
		maxPerRange = 10000
	}

	var ips []net.IP

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

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

	for _, p := range data.Data.IPv4Prefixes {
		_, network, err := net.ParseCIDR(p.Prefix)
		if err != nil {
			continue
		}

		ip := make(net.IP, len(network.IP))
		copy(ip, network.IP.Mask(network.Mask))

		count := 0
		for network.Contains(ip) && count < maxPerRange {
			tmp := make(net.IP, len(ip))
			copy(tmp, ip)
			ips = append(ips, tmp)
			incrementIP(ip)
			count++
		}
	}

	return ips, nil
}

func collectBGPRanges() ([]net.IP, error) {

	var ips []net.IP

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

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
				Prefix string `json:"ipv6_prefixes"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	const maxPerPrefix = 10000

	for _, p := range data.Data.IPv4Prefixes {

		_, network, err := net.ParseCIDR(p.Prefix)
		if err != nil {
			continue
		}

		ip := make(net.IP, len(network.IP))
		copy(ip, network.IP.Mask(network.Mask))

		count := 0

		for network.Contains(ip) && count < maxPerPrefix {

			tmp := make(net.IP, len(ip))
			copy(tmp, ip)

			ips = append(ips, tmp)

			incrementIP(ip)
			count++
		}
	}

	return ips, nil
}

func collectASNRange() ([]net.IP, error) {
	return collectCloudflareIPs()
}

func collectCustomIPs() ([]net.IP, error) {
	var ips []net.IP
	return ips, nil
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
			_, network, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}

			ip := network.IP.Mask(network.Mask)
			for network.Contains(ip) {
				ips = append(ips, net.ParseIP(ip.String()))
				incrementIP(ip)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

func collectHistoricalIPs() ([]net.IP, error) {
	var ips []net.IP
	return ips, nil
}

func collectIPv6Range() ([]net.IP, error) {
	var ips []net.IP

	ranges := []string{
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
		"2405:b500::/32", "2405:8100::/32", "2c0f:f248::/32",
		"2a06:98c0::/29",
	}

	for _, cidr := range ranges {
		_, network, _ := net.ParseCIDR(cidr)
		if network == nil {
			continue
		}

		count := 0
		ip := network.IP.Mask(network.Mask)
		for network.Contains(ip) && count < 1000 {
			ips = append(ips, net.ParseIP(ip.String()))
			incrementIP(ip)
			count++
		}
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func exportResults(results []ScanResult, config *ScanConfig) error {
	switch config.OutputFormat {
	case "json":
		return exportJSON(results, config.OutputPath)
	case "yaml":
		return exportYAML(results, config.OutputPath)
	case "csv":
		return exportCSV(results, config.OutputPath)
	case "txt":
		return exportTXT(results, config.OutputPath)
	default:
		return exportJSON(results, config.OutputPath)
	}
}

func exportJSON(results []ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func exportYAML(results []ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	return encoder.Encode(results)
}

func exportCSV(results []ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"ip", "port", "is_alive", "is_cloudflare", "score", "source",
		"country", "city", "region", "asn", "hostname", "is_proxy",
		"edge_type", "tls_version", "tls_cipher", "tls_alpn", "tls_sni",
		"cert_issuer", "cert_san", "cert_expiry", "http_version",
		"http2_supported", "http3_supported", "cf_ray", "cf_cache_status",
		"server_header", "cf_request_id", "tcp_connect_ms", "tls_handshake_ms",
		"ttfb_ms", "download_speed_1mb", "download_speed_10mb", "packet_loss",
		"average_latency", "median_latency", "jitter", "http11", "scanned_at",
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		record := []string{
			r.IP, strconv.Itoa(r.Port), fmt.Sprintf("%v", r.IsAlive),
			fmt.Sprintf("%v", r.IsCloudflare), strconv.Itoa(r.Score), r.Source,
			r.Country, r.City, r.Region, r.ASN, r.Hostname,
			fmt.Sprintf("%v", r.IsProxy), r.EdgeType, r.TLSVersion,
			r.TLSCipher, r.TLSALPN, r.TLSSNI, r.CertIssuer, r.CertSAN,
			r.CertExpiry.Format(time.RFC3339), r.HTTPVersion,
			fmt.Sprintf("%v", r.HTTP2Supported), fmt.Sprintf("%v", r.HTTP3Supported),
			r.CFRay, r.CFCacheStatus, r.ServerHeader, r.CFRequestID,
			fmt.Sprintf("%.2f", r.TCPConnectMs), fmt.Sprintf("%.2f", r.TLSHandshakeMs),
			fmt.Sprintf("%.2f", r.TTFBMs), fmt.Sprintf("%.2f", r.DownloadSpeed1MB),
			fmt.Sprintf("%.2f", r.DownloadSpeed10MB), fmt.Sprintf("%.2f", r.PacketLoss),
			fmt.Sprintf("%.2f", r.AverageLatency), fmt.Sprintf("%.2f", r.MedianLatency),
			fmt.Sprintf("%.2f", r.Jitter), fmt.Sprintf("%v", r.HTTP11),
			r.ScannedAt.Format(time.RFC3339),
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func exportTXT(results []ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, r := range results {
		if r.IsAlive {
			fmt.Fprintf(file, "%s:%d\n", r.IP, r.Port)
		}
	}

	return nil
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
  -source <source>         IP sources (comma-separated): cloudflare, bgp, asn13335, ipv6
                           or custom:filename.txt (default: cloudflare)
  -workers <num>           Number of concurrent workers (default: 100)
  -ports <ports>           Ports to scan (comma-separated) (default: 443,80,2053,2083,2087,2096,8443)
  -domain <domain>         Test domain for validation (default: www.cloudflare.com)
  -output <path>           Output file path (default: results.json)
  -format <format>         Output format: json, yaml, csv, txt (default: json)
  -geoip <path>            GeoIP database path for location info
  -speed                   Enable speed test
  -http3                   Enable HTTP/3 detection (default: true)
  -http2                   Enable HTTP/2 detection (default: true)
  -rdns                    Enable reverse DNS lookup (default: true)
  -timeout <seconds>       HTTP/TLS timeout in seconds (default: 5)
  -port-timeout <seconds>  Port scan timeout in seconds (default: 2)
  -rate <num>              Rate limit per second (default: 1000)
  -max <num>               Maximum results to show (default: 20)
  -sort <sort>             Sort by: score, latency (default: score)
  -quiet                   Disable real-time output
  -noprogress              Disable progress display
  -nocolor                 Disable colors
  -help                    Show this help message

Examples:
  cf.exe -workers 200 -source cloudflare -output results.json
  cf.exe -source custom:ips.txt -ports 443,8443 -format csv -output scan.csv
  cf.exe -workers 50 -geoip GeoLite2-City.mmdb -speed -http3
  cf.exe -source cloudflare,bgp -domain example.com -workers 300 -sort latency`)
}

func main() {
	config := &ScanConfig{
		Sources:          []string{"cloudflare"},
		WorkerCount:      100,
		Ports:            []int{443, 80, 2053, 2083, 2087, 2096, 8443},
		EnableHTTP2:      true,
		EnableHTTP3:      true,
		EnableSpeedTest:  false,
		EnableGeoIP:      false,
		EnableReverseDNS: true,
		OutputFormat:     "json",
		OutputPath:       "results.json",
		TestDomain:       "www.cloudflare.com",
		RateLimit:        1000,
		RealTimePrint:    true,
		ShowProgress:     true,
		MaxResults:       20,
		Timeout:          5,
		PortScanTimeout:  2,
		SortBy:           "score",
		NoColor:          false,
		MaxIPsPerRange:   10000,
	}

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-help", "-h", "--help":
			showHelp()
			return
		case "-source":
			if i+1 < len(os.Args) {
				config.Sources = strings.Split(os.Args[i+1], ",")
				i++
			}
		case "-workers":
			if i+1 < len(os.Args) {
				config.WorkerCount, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-ports":
			if i+1 < len(os.Args) {
				portStrs := strings.Split(os.Args[i+1], ",")
				var ports []int
				for _, p := range portStrs {
					if port, err := strconv.Atoi(p); err == nil {
						ports = append(ports, port)
					}
				}
				config.Ports = ports
				i++
			}
		case "-domain":
			if i+1 < len(os.Args) {
				config.TestDomain = os.Args[i+1]
				i++
			}
		case "-output":
			if i+1 < len(os.Args) {
				config.OutputPath = os.Args[i+1]
				i++
			}
		case "-format":
			if i+1 < len(os.Args) {
				config.OutputFormat = os.Args[i+1]
				i++
			}
		case "-geoip":
			if i+1 < len(os.Args) {
				config.GeoIPDBPath = os.Args[i+1]
				config.EnableGeoIP = true
				i++
			}
		case "-speed":
			config.EnableSpeedTest = true
		case "-http3":
			config.EnableHTTP3 = true
		case "-http2":
			config.EnableHTTP2 = true
		case "-rdns":
			config.EnableReverseDNS = true
		case "-timeout":
			if i+1 < len(os.Args) {
				config.Timeout, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-port-timeout":
			if i+1 < len(os.Args) {
				config.PortScanTimeout, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-rate":
			if i+1 < len(os.Args) {
				config.RateLimit, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-max":
			if i+1 < len(os.Args) {
				config.MaxResults, _ = strconv.Atoi(os.Args[i+1])
				i++
			}
		case "-sort":
			if i+1 < len(os.Args) {
				config.SortBy = os.Args[i+1]
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

	geoDB, _ := loadGeoDB(config.GeoIPDBPath)

	ips, err := collectIPs(config)
	if err != nil {
		fmt.Println("Error collecting IPs:", err)
		os.Exit(1)
	}

	fmt.Printf("Collected %d IPs to scan\n", len(ips))
	fmt.Printf("Using %d workers, scanning ports: %v\n", config.WorkerCount, config.Ports)
	fmt.Printf("Sort by: %s\n", config.SortBy)
	fmt.Println("Scanning... (press Ctrl+C to stop)\n")

	pool := NewWorkerPool(config, geoDB)
	pool.stats.Total = int64(len(ips))

	var wg sync.WaitGroup
	pool.Start(&wg)

	var results []ScanResult
	var resultsMu sync.Mutex

	var collector sync.WaitGroup

	collector.Add(1)

	go func() {
		defer collector.Done()

		for result := range pool.results {
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}
	}()

	for _, ip := range ips {
		select {
		case pool.jobs <- ip:
		case <-pool.ctx.Done():
			goto cleanup
		}
	}

	close(pool.jobs)
	wg.Wait()
	close(pool.results)

cleanup:
	pool.cancel()

	if pool.validFile != nil {
		pool.validFile.Close()
	}

	fmt.Printf("\n\nScan Complete!\n")
	fmt.Printf("Total: %d | Alive: %d | Dead: %d | HTTP3: %d | Best: %.2fms | Time: %s\n",
		pool.stats.Total, pool.stats.Alive, pool.stats.Dead, pool.stats.HTTP3,
		pool.stats.BestLatency, time.Since(pool.startTime).Round(time.Second))

	sort.Slice(results, func(i, j int) bool {
		if config.SortBy == "latency" {
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

	if err := exportResults(results, config); err != nil {
		fmt.Println("Error exporting results:", err)
	} else {
		fmt.Printf("Results exported to %s\n", config.OutputPath)
	}

	fmt.Printf("\nTop %d results:\n", config.MaxResults)
	aliveCount := 0
	for _, r := range results {
		if r.IsAlive && aliveCount < config.MaxResults {
			cf := "✗"
			if r.IsCloudflare {
				cf = "✓"
			}
			h2 := "✗"
			if r.HTTP2Supported {
				h2 = "✓"
			}
			h3 := "✗"
			if r.HTTP3Supported {
				h3 = "✓"
			}
			fmt.Printf("%-15s Score:%3d Lat:%7.2fms CF:%s H2:%s H3:%s Ray:%s\n",
				r.IP, r.Score, r.TCPConnectMs, cf, h2, h3, r.CFRay)
			aliveCount++
		}
	}
}

func RunScanner(config *ScanConfig) error {
	geoDB, _ := loadGeoDB(config.GeoIPDBPath)

	ips, err := collectIPs(config)
	if err != nil {
		return fmt.Errorf("error collecting IPs: %v", err)
	}

	fmt.Printf("Collected %d IPs to scan\n", len(ips))
	fmt.Printf("Using %d workers, scanning ports: %v\n", config.WorkerCount, config.Ports)
	fmt.Printf("Sort by: %s\n", config.SortBy)
	fmt.Printf("Output will be saved to: %s\n", config.OutputPath)
	fmt.Println("Scanning... (press Ctrl+C to stop)\n")

	pool := NewWorkerPool(config, geoDB)
	pool.stats.Total = int64(len(ips))

	var wg sync.WaitGroup
	pool.Start(&wg)

	var results []ScanResult
	var resultsMu sync.Mutex

	go func() {
		for result := range pool.results {
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}
	}()

	for _, ip := range ips {
		select {
		case pool.jobs <- ip:
		case <-pool.ctx.Done():
			goto cleanup
		}
	}

	close(pool.jobs)
	wg.Wait()
	close(pool.results)

cleanup:
	pool.cancel()

	if pool.validFile != nil {
		pool.validFile.Close()
		fmt.Printf("\nValid IPs saved to: %s\n", pool.validFile.Name())
	}

	fmt.Printf("\n\nScan Complete!\n")
	fmt.Printf("Total: %d | Alive: %d | Dead: %d | HTTP3: %d | Best: %.2fms | Time: %s\n",
		pool.stats.Total, pool.stats.Alive, pool.stats.Dead, pool.stats.HTTP3,
		pool.stats.BestLatency, time.Since(pool.startTime).Round(time.Second))

	sort.Slice(results, func(i, j int) bool {
		if config.SortBy == "latency" {
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

	if err := exportResults(results, config); err != nil {
		return fmt.Errorf("error exporting results: %v", err)
	}
	fmt.Printf("Full results exported to: %s\n", config.OutputPath)

	fmt.Printf("\nTop %d results:\n", config.MaxResults)
	aliveCount := 0
	for _, r := range results {
		if r.IsAlive && aliveCount < config.MaxResults {
			cf := "✗"
			if r.IsCloudflare {
				cf = "✓"
			}
			h2 := "✗"
			if r.HTTP2Supported {
				h2 = "✓"
			}
			h3 := "✗"
			if r.HTTP3Supported {
				h3 = "✓"
			}
			fmt.Printf("%-15s Score:%3d Lat:%7.2fms CF:%s H2:%s H3:%s Ray:%s\n",
				r.IP, r.Score, r.TCPConnectMs, cf, h2, h3, r.CFRay)
			aliveCount++
		}
	}

	return nil
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
	totalRanges := 0

	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ones, bits := network.Mask.Size()

		totalIPs := int64(1 << uint(bits-ones))
		
		if totalIPs < int64(maxIPsPerRange) {
			totalTargets += totalIPs
		} else {
			totalTargets += int64(maxIPsPerRange)
		}
		totalRanges++
	}

	totalChecks := totalTargets * int64(len(ports))

	const avgPerCheck = 0.1 

	seconds := float64(totalChecks) * avgPerCheck / float64(workers)

	var (
		text  string
		color string
	)

	switch {
	case seconds < 10:
		text = fmt.Sprintf("%.0f sec", seconds)
		color = Green
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
