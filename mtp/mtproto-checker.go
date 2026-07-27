package mtp

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CheckerConfig struct {
	File       string
	Download   bool
	OutputFile string
	NoColor    bool
	Threads    int
	Timeout    time.Duration
	Sources    []string
}

type ProxyEntry struct {
	Raw    string
	Server string
	Port   int
	Secret string
}

type Result struct {
	Entry   ProxyEntry
	Healthy bool
	Latency time.Duration
	Err     error
}

type Checker struct {
	cfg        CheckerConfig
	results    []Result
	mu         sync.Mutex
	done       chan struct{}
	outputFile *os.File
	fileMu     sync.Mutex
}

var (
	reHex32 = regexp.MustCompile(`(?i)\b[a-f0-9]{32}\b`)
	reHex64 = regexp.MustCompile(`(?i)\b[a-f0-9]{64}\b`)
)

const (
	cReset  = "\033[0m"
	cGreen  = "\033[32m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cBlue   = "\033[34m"
)

func NewChecker(cfg CheckerConfig) *Checker {
	if cfg.Threads <= 0 {
		cfg.Threads = 20
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if len(cfg.Sources) == 0 {
		cfg.Sources = []string{
			"https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
			"https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
		}
	}
	if cfg.OutputFile == "" {
		cfg.OutputFile = "valid_mtproto.txt"
	}
	return &Checker{
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

func (c *Checker) Run() error {
	defer closeOnce(c.done)

	if c.cfg.Download {
		printInfo("starting download")
		printInfo("sources:")
		for _, s := range c.cfg.Sources {
			fmt.Printf("%s  - %s%s\n", cBlue, s, cReset)
		}
	}

	items, err := c.collectItems()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("no proxy entries found")
	}

	printInfo(fmt.Sprintf("checking %d proxies with %d threads and %v timeout", len(items), c.cfg.Threads, c.cfg.Timeout))

	if c.cfg.OutputFile != "" {
		file, err := os.Create(c.cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		c.outputFile = file
		defer c.outputFile.Close()

		header := fmt.Sprintf("# MTProto Proxies - Checked at %s\n", time.Now().Format(time.RFC3339))
		c.outputFile.WriteString(header)
	}

	results, err := c.CheckManyRealtime(context.Background(), items, c.cfg.Threads, c.cfg.Timeout, c.cfg.NoColor)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.results = results
	c.mu.Unlock()

	printSummary(results, c.cfg.NoColor)
	return nil
}

func (c *Checker) collectItems() ([]string, error) {
	var items []string

	if c.cfg.Download {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		dl, available := DownloadMTProtoList(ctx, c.cfg.Sources)
		if len(available) > 0 {
			printInfo("available sources:")
			for _, s := range available {
				fmt.Printf("%s  + %s%s\n", cGreen, s, cReset)
			}
		}
		items = append(items, dl...)
	}

	if c.cfg.File != "" {
		fromFile, err := LoadFromFile(c.cfg.File)
		if err != nil {
			return nil, err
		}
		items = append(items, fromFile...)
	}

	return dedupeNonEmpty(items), nil
}

func (c *Checker) Results() []Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Result, len(c.results))
	copy(out, c.results)
	return out
}

func (c *Checker) Wait() {
	<-c.done
}

func closeOnce(ch chan struct{}) {
	defer func() { recover() }()
	close(ch)
}

func printInfo(msg string) {
	fmt.Printf("%s[i]%s %s\n", cBlue, cReset, msg)
}

func dedupeNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func DownloadMTProtoList(ctx context.Context, sources []string) ([]string, []string) {
	client := &http.Client{Timeout: 15 * time.Second}
	seen := map[string]struct{}{}
	var out []string
	var available []string

	for _, s := range sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		available = append(available, s)
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if _, err := ParseProxyLine(line); err != nil {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			out = append(out, line)
		}
	}

	return out, available
}

func LoadFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func ParseProxyLine(raw string) (ProxyEntry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ProxyEntry{}, errors.New("empty line")
	}

	if strings.Contains(raw, "t.me/proxy") || strings.HasPrefix(raw, "tg://proxy") {
		if u, err := url.Parse(raw); err == nil {
			q := u.Query()
			server := q.Get("server")
			portStr := q.Get("port")
			secret := q.Get("secret")
			if server != "" && portStr != "" && secret != "" {
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return ProxyEntry{}, err
				}
				return ProxyEntry{Raw: raw, Server: server, Port: port, Secret: secret}, nil
			}
		}
	}

	if strings.Contains(raw, "server=") && strings.Contains(raw, "port=") && strings.Contains(raw, "secret=") {
		var server, secret string
		var port int
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '|'
		}) {
			p := strings.TrimSpace(part)
			lp := strings.ToLower(p)
			if strings.HasPrefix(lp, "server=") {
				server = strings.TrimSpace(strings.SplitN(p, "=", 2)[1])
			}
			if strings.HasPrefix(lp, "port=") {
				v, _ := strconv.Atoi(strings.TrimSpace(strings.SplitN(p, "=", 2)[1]))
				port = v
			}
			if strings.HasPrefix(lp, "secret=") {
				secret = strings.TrimSpace(strings.SplitN(p, "=", 2)[1])
			}
		}
		if server != "" && port > 0 && secret != "" {
			return ProxyEntry{Raw: raw, Server: server, Port: port, Secret: secret}, nil
		}
	}

	if fields := strings.Fields(raw); len(fields) >= 3 {
		server := fields[0]
		port, _ := strconv.Atoi(fields[1])
		secret := fields[2]
		if server != "" && port > 0 && secret != "" {
			return ProxyEntry{Raw: raw, Server: server, Port: port, Secret: secret}, nil
		}
	}

	_ = reHex32
	_ = reHex64
	return ProxyEntry{}, fmt.Errorf("invalid proxy line")
}

func CheckProxy(ctx context.Context, e ProxyEntry, timeout time.Duration) Result {
	start := time.Now()
	res := Result{Entry: e}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", e.Server, e.Port))
	if err != nil {
		res.Err = err
		return res
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	secretBytes, err := decodeSecret(e.Secret)
	if err != nil {
		res.Err = err
		return res
	}

	payload := make([]byte, 16)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	_, _ = rnd.Read(payload)
	copy(payload[:16], secretBytes[:16])

	if _, err := conn.Write(payload); err != nil {
		res.Err = err
		return res
	}

	reply := make([]byte, 1)
	if _, err := conn.Read(reply); err != nil {
		res.Err = err
		return res
	}

	res.Healthy = true
	res.Latency = time.Since(start)
	return res
}

func decodeSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	if s == "" {
		return nil, errors.New("empty secret")
	}

	s = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			return r
		}
		return -1
	}, s)

	if len(s) == 0 {
		return nil, errors.New("secret contains no valid hex characters")
	}

	if strings.HasPrefix(s, "dd") || strings.HasPrefix(s, "ee") {
		s = s[2:]
	}

	if len(s)%2 == 1 {
		s = "0" + s
	}

	if len(s) < 32 {
		s = strings.Repeat("0", 32-len(s)) + s
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex secret: %w", err)
	}

	if len(b) < 16 {
		return nil, errors.New("secret too short")
	}

	return b[:16], nil
}

func isHexString(s string) bool {
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func (c *Checker) CheckManyRealtime(ctx context.Context, items []string, threads int, timeout time.Duration, noColor bool) ([]Result, error) {
	if threads <= 0 {
		threads = 20
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	entries := make([]ProxyEntry, 0, len(items))
	for _, s := range items {
		e, err := ParseProxyLine(s)
		if err == nil {
			entries = append(entries, e)
		}
	}

	jobs := make(chan ProxyEntry)
	results := make(chan Result, len(entries))
	var wg sync.WaitGroup
	var resultMu sync.Mutex
	out := make([]Result, 0, len(entries))

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range jobs {
				result := CheckProxy(ctx, e, timeout)

				if result.Healthy {
					c.saveHealthyProxy(result.Entry)
				}

				results <- result
			}
		}()
	}

	go func() {
		for _, e := range entries {
			select {
			case jobs <- e:
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for r := range results {
		resultMu.Lock()
		out = append(out, r)
		resultMu.Unlock()
		printRealtime(r, noColor)
	}

	return out, nil
}

func (c *Checker) saveHealthyProxy(entry ProxyEntry) {
	if c.outputFile == nil {
		return
	}

	c.fileMu.Lock()
	defer c.fileMu.Unlock()

	_, err := c.outputFile.WriteString(entry.Raw + "\n")
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
	}

	c.outputFile.Sync()
}

func printRealtime(r Result, noColor bool) {
	show := r.Entry.Server
	if r.Entry.Port > 0 {
		show = fmt.Sprintf("%s:%d", r.Entry.Server, r.Entry.Port)
	}
	if r.Healthy {
		if noColor {
			fmt.Printf("[OK] %s | %v\n", show, r.Latency)
		} else {
			fmt.Printf("%s[OK]%s %s%s%s | %s%s%s\n", cGreen, cReset, cCyan, show, cReset, cYellow, r.Latency, cReset)
		}
		return
	}
	if noColor {
		fmt.Printf("[BAD] %s | %v\n", show, r.Err)
	} else {
		fmt.Printf("%s[BAD]%s %s%s%s | %v\n", cRed, cReset, cCyan, show, cReset, r.Err)
	}
}

func WriteHealthy(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, r := range results {
		if r.Healthy {
			_, _ = fmt.Fprintln(w, r.Entry.Raw)
		}
	}
	return w.Flush()
}

func printSummary(results []Result, noColor bool) {
	okCount := 0
	badCount := 0
	for _, r := range results {
		if r.Healthy {
			okCount++
		} else {
			badCount++
		}
	}
	if noColor {
		fmt.Printf("\nOK: %d | BAD: %d | TOTAL: %d\n", okCount, badCount, len(results))
		return
	}
	fmt.Printf("\n%sOK:%s %d | %sBAD:%s %d | %sTOTAL:%s %d\n", cGreen, cReset, okCount, cRed, cReset, badCount, cYellow, cReset, len(results))
}
