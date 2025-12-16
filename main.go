package main

import (
        "bufio"
        "context"
        "crypto/md5"
        "crypto/tls"
        "encoding/base64"
        "encoding/csv"
        "encoding/json"
        "flag"
        "fmt"
        "io"
        "net"
        "net/http"
        "os"
        "os/signal"
        "regexp"
        "strings"
        "sync"
        "sync/atomic"
        "syscall"
        "time"

        "golang.org/x/time/rate"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NORDIC COLORS (soft, pastel, more white)
// ═══════════════════════════════════════════════════════════════════════════════

const (
        reset   = "\033[0m"
        white   = "\033[97m"
        gray    = "\033[37m"
        dimGray = "\033[90m"
        blue    = "\033[94m"
        cyan    = "\033[96m"
        green   = "\033[92m"
        yellow  = "\033[93m"
        bold    = "\033[1m"
)

func nordic(s string) string       { return white + s + reset }
func nordicDim(s string) string    { return dimGray + s + reset }
func nordicAccent(s string) string { return cyan + s + reset }
func nordicGreen(s string) string  { return green + s + reset }
func nordicBold(s string) string   { return bold + white + s + reset }

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

type ScanResult struct {
        Domain          string           `json:"domain"`
        IsCloudflare    bool             `json:"is_cloudflare"`
        CloudflareIPs   []string         `json:"cloudflare_ips,omitempty"`
        SubdomainsFound int              `json:"subdomains_found"`
        CandidateIPs    []string         `json:"candidate_ips"`
        MXIPs           []string         `json:"mx_ips,omitempty"`
        SPFIPs          []string         `json:"spf_ips,omitempty"`
        HistoricalIPs   []string         `json:"historical_ips,omitempty"`
        WaybackSubs     []string         `json:"wayback_subs,omitempty"`
        CrimeFlareIP    string           `json:"crimeflare_ip,omitempty"`
        ViewDNSIPs      []string         `json:"viewdns_ips,omitempty"`
        IPv6Addrs       []string         `json:"ipv6_addrs,omitempty"`
        ThreatCrowdIPs  []string         `json:"threatcrowd_ips,omitempty"`
        FaviconHash     string           `json:"favicon_hash,omitempty"`
        VerifiedOrigins []VerifiedOrigin `json:"verified_origins,omitempty"`
        ScanTime        float64          `json:"scan_time"`
        Error           string           `json:"error,omitempty"`
}

type VerifiedOrigin struct {
        IP         string  `json:"ip"`
        Confidence float64 `json:"confidence"`
        Method     string  `json:"method"`
        StatusCode int     `json:"status_code,omitempty"`
}

type Config struct {
        Workers   int
        Timeout   int
        RateLimit float64
        Verbose   bool
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUDFLARE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

var cloudflareRanges = []string{
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

var cfNets []*net.IPNet

func init() {
        for _, cidr := range cloudflareRanges {
                _, ipNet, err := net.ParseCIDR(cidr)
                if err == nil {
                        cfNets = append(cfNets, ipNet)
                }
        }
}

func isCloudflareIP(ipStr string) bool {
        ip := net.ParseIP(ipStr)
        if ip == nil {
                return false
        }
        for _, cfNet := range cfNets {
                if cfNet.Contains(ip) {
                        return true
                }
        }
        return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// DNS RESOLVER
// ═══════════════════════════════════════════════════════════════════════════════

type DNSResolver struct {
        resolver *net.Resolver
        timeout  time.Duration
}

func newDNSResolver(timeout time.Duration) *DNSResolver {
        return &DNSResolver{
                resolver: &net.Resolver{
                        PreferGo: true,
                        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                                d := net.Dialer{Timeout: timeout}
                                return d.DialContext(ctx, "udp", "8.8.8.8:53")
                        },
                },
                timeout: timeout,
        }
}

func (r *DNSResolver) resolve(domain string) ([]string, bool, error) {
        ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
        defer cancel()

        ips, err := r.resolver.LookupIP(ctx, "ip4", domain)
        if err != nil {
                return nil, false, err
        }

        var result []string
        isCF := false
        for _, ip := range ips {
                ipStr := ip.String()
                result = append(result, ipStr)
                if isCloudflareIP(ipStr) {
                        isCF = true
                }
        }
        return result, isCF, nil
}

func (r *DNSResolver) resolveBulk(domains []string, workers int) map[string][]string {
        results := make(map[string][]string)
        var mu sync.Mutex
        var wg sync.WaitGroup

        jobs := make(chan string, len(domains))
        for _, d := range domains {
                jobs <- d
        }
        close(jobs)

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for domain := range jobs {
                                ips, isCF, err := r.resolve(domain)
                                if err == nil && !isCF {
                                        mu.Lock()
                                        for _, ip := range ips {
                                                if !isCloudflareIP(ip) {
                                                        results[domain] = append(results[domain], ip)
                                                }
                                        }
                                        mu.Unlock()
                                }
                        }
                }()
        }
        wg.Wait()
        return results
}

func (r *DNSResolver) getMXIPs(domain string) []string {
        ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
        defer cancel()

        mxs, err := r.resolver.LookupMX(ctx, domain)
        if err != nil {
                return nil
        }

        var ips []string
        for _, mx := range mxs {
                host := strings.TrimSuffix(mx.Host, ".")
                mxIPs, err := r.resolver.LookupIP(ctx, "ip4", host)
                if err == nil {
                        for _, ip := range mxIPs {
                                ipStr := ip.String()
                                if !isCloudflareIP(ipStr) {
                                        ips = append(ips, ipStr)
                                }
                        }
                }
        }
        return ips
}

func (r *DNSResolver) getSPFIPs(domain string) []string {
        ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
        defer cancel()

        txts, err := r.resolver.LookupTXT(ctx, domain)
        if err != nil {
                return nil
        }

        ipRegex := regexp.MustCompile(`ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
        var ips []string
        seen := make(map[string]bool)

        for _, txt := range txts {
                if strings.Contains(strings.ToLower(txt), "spf") {
                        matches := ipRegex.FindAllStringSubmatch(txt, -1)
                        for _, m := range matches {
                                if len(m) > 1 && !seen[m[1]] && !isCloudflareIP(m[1]) {
                                        seen[m[1]] = true
                                        ips = append(ips, m[1])
                                }
                        }
                }
        }
        return ips
}

func (r *DNSResolver) getIPv6(domain string) []string {
        ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
        defer cancel()

        ips, err := r.resolver.LookupIP(ctx, "ip6", domain)
        if err != nil {
                return nil
        }

        var result []string
        for _, ip := range ips {
                result = append(result, ip.String())
        }
        return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRT.SH MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type CrtshModule struct {
        client  *http.Client
        limiter *rate.Limiter
}

func newCrtsh(timeout time.Duration, rateLimit float64) *CrtshModule {
        return &CrtshModule{
                client: &http.Client{
                        Timeout: timeout,
                        Transport: &http.Transport{
                                MaxIdleConns:        100,
                                MaxIdleConnsPerHost: 10,
                        },
                },
                limiter: rate.NewLimiter(rate.Limit(rateLimit), 1),
        }
}

type certEntry struct {
        NameValue string `json:"name_value"`
}

func (c *CrtshModule) getSubdomains(ctx context.Context, domain string) ([]string, error) {
        if err := c.limiter.Wait(ctx); err != nil {
                return nil, err
        }

        url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := c.client.Do(req)
        if err != nil {
                return []string{domain}, nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        var entries []certEntry
        if json.Unmarshal(body, &entries) != nil {
                return []string{domain}, nil
        }

        seen := make(map[string]bool)
        var subs []string
        for _, e := range entries {
                for _, name := range strings.Split(e.NameValue, "\n") {
                        name = strings.TrimSpace(strings.ToLower(name))
                        if name != "" && !strings.Contains(name, "*") && strings.HasSuffix(name, domain) && !seen[name] {
                                seen[name] = true
                                subs = append(subs, name)
                        }
                }
        }
        if len(subs) == 0 {
                subs = []string{domain}
        }
        return subs, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// WAYBACK MACHINE MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type WaybackModule struct {
        client  *http.Client
        limiter *rate.Limiter
}

func newWayback(timeout time.Duration, rateLimit float64) *WaybackModule {
        return &WaybackModule{
                client:  &http.Client{Timeout: timeout},
                limiter: rate.NewLimiter(rate.Limit(rateLimit), 1),
        }
}

func (w *WaybackModule) getSubdomains(ctx context.Context, domain string) []string {
        if err := w.limiter.Wait(ctx); err != nil {
                return nil
        }

        url := fmt.Sprintf("https://web.archive.org/cdx/search?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=5000", domain)
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := w.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)

        var results [][]string
        if json.Unmarshal(body, &results) != nil {
                return nil
        }

        subRegex := regexp.MustCompile(`https?://([a-zA-Z0-9._-]+\.)` + regexp.QuoteMeta(domain))
        seen := make(map[string]bool)
        var subs []string

        for _, row := range results {
                if len(row) > 0 {
                        matches := subRegex.FindStringSubmatch(row[0])
                        if len(matches) > 0 {
                                sub := strings.ToLower(strings.TrimSuffix(matches[0], "/"))
                                sub = strings.TrimPrefix(sub, "http://")
                                sub = strings.TrimPrefix(sub, "https://")
                                sub = strings.Split(sub, "/")[0]
                                if !seen[sub] && strings.HasSuffix(sub, domain) {
                                        seen[sub] = true
                                        subs = append(subs, sub)
                                }
                        }
                }
        }
        return subs
}

// ═══════════════════════════════════════════════════════════════════════════════
// RAPIDDNS MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type RapidDNSModule struct {
        client  *http.Client
        limiter *rate.Limiter
}

func newRapidDNS(timeout time.Duration, rateLimit float64) *RapidDNSModule {
        return &RapidDNSModule{
                client:  &http.Client{Timeout: timeout},
                limiter: rate.NewLimiter(rate.Limit(rateLimit), 1),
        }
}

func (r *RapidDNSModule) getSubdomains(ctx context.Context, domain string) []string {
        if err := r.limiter.Wait(ctx); err != nil {
                return nil
        }

        url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := r.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        content := string(body)

        subRegex := regexp.MustCompile(`([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
        matches := subRegex.FindAllString(content, -1)

        seen := make(map[string]bool)
        var subs []string
        for _, m := range matches {
                m = strings.ToLower(m)
                if !seen[m] {
                        seen[m] = true
                        subs = append(subs, m)
                }
        }
        return subs
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUBDOMAIN.CENTER MODULE (very comprehensive free API)
// ═══════════════════════════════════════════════════════════════════════════════

type SubdomainCenterModule struct {
        client  *http.Client
        limiter *rate.Limiter
}

func newSubdomainCenter(timeout time.Duration) *SubdomainCenterModule {
        return &SubdomainCenterModule{
                client:  &http.Client{Timeout: timeout},
                limiter: rate.NewLimiter(rate.Limit(0.05), 1), // 3 req/min = 0.05/sec
        }
}

func (s *SubdomainCenterModule) getSubdomains(ctx context.Context, domain string) []string {
        shortCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        if err := s.limiter.Wait(shortCtx); err != nil {
                return nil
        }

        url := fmt.Sprintf("https://api.subdomain.center/?domain=%s", domain)
        req, _ := http.NewRequestWithContext(shortCtx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := s.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 500*1024))

        var subs []string
        json.Unmarshal(body, &subs)

        seen := make(map[string]bool)
        var unique []string
        for _, sub := range subs {
                sub = strings.ToLower(sub)
                if !seen[sub] && strings.HasSuffix(sub, domain) {
                        seen[sub] = true
                        unique = append(unique, sub)
                }
        }
        return unique
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREATCROWD MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type ThreatCrowdModule struct {
        client  *http.Client
        limiter *rate.Limiter
}

func newThreatCrowd(timeout time.Duration) *ThreatCrowdModule {
        return &ThreatCrowdModule{
                client:  &http.Client{Timeout: timeout},
                limiter: rate.NewLimiter(rate.Limit(0.1), 1),
        }
}

func (t *ThreatCrowdModule) getSubdomains(ctx context.Context, domain string) []string {
        shortCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
        defer cancel()

        if err := t.limiter.Wait(shortCtx); err != nil {
                return nil
        }

        url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
        req, _ := http.NewRequestWithContext(shortCtx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := t.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 200*1024))

        type tcResponse struct {
                Subdomains   []string `json:"subdomains"`
                Resolutions  []struct {
                        IPAddress string `json:"ip_address"`
                } `json:"resolutions"`
        }

        var result tcResponse
        if json.Unmarshal(body, &result) != nil {
                return nil
        }
        return result.Subdomains
}

func (t *ThreatCrowdModule) getIPs(ctx context.Context, domain string) []string {
        shortCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
        defer cancel()

        if err := t.limiter.Wait(shortCtx); err != nil {
                return nil
        }

        url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
        req, _ := http.NewRequestWithContext(shortCtx, "GET", url, nil)

        resp, err := t.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 200*1024))

        type tcResponse struct {
                Resolutions []struct {
                        IPAddress string `json:"ip_address"`
                } `json:"resolutions"`
        }

        var result tcResponse
        if json.Unmarshal(body, &result) != nil {
                return nil
        }

        ipRegex := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
        var ips []string
        for _, r := range result.Resolutions {
                if ipRegex.MatchString(r.IPAddress) && !isCloudflareIP(r.IPAddress) {
                        ips = append(ips, r.IPAddress)
                }
        }
        return ips
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMMON SUBDOMAINS CHECK
// ═══════════════════════════════════════════════════════════════════════════════

var commonSubdomains = []string{
        "direct", "direct-connect", "origin", "origin-www", "origin-server",
        "real", "realip", "backend", "server", "www-origin",
        "mail", "email", "smtp", "pop", "imap", "webmail", "mx",
        "ftp", "sftp", "cpanel", "whm", "plesk", "panel", "admin",
        "dev", "development", "staging", "stage", "test", "testing", "qa",
        "api", "api1", "api2", "app", "apps", "mobile",
        "cdn", "static", "assets", "media", "images", "img",
        "vpn", "remote", "gateway", "ns1", "ns2", "dns",
        "old", "old-www", "legacy", "backup", "bak",
        "shop", "store", "portal", "secure", "ssl",
}

// ═══════════════════════════════════════════════════════════════════════════════
// DNS HISTORY MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type HistoryModule struct {
        client  *http.Client
        limiter *rate.Limiter
}

func newHistory(timeout time.Duration, rateLimit float64) *HistoryModule {
        return &HistoryModule{
                client:  &http.Client{Timeout: timeout},
                limiter: rate.NewLimiter(rate.Limit(rateLimit), 1),
        }
}

func (h *HistoryModule) getHistoricalIPs(ctx context.Context, domain string) []string {
        var allIPs []string
        htIPs := h.checkHackerTarget(ctx, domain)
        allIPs = append(allIPs, htIPs...)
        avIPs := h.checkAlienVault(ctx, domain)
        allIPs = append(allIPs, avIPs...)

        seen := make(map[string]bool)
        var unique []string
        for _, ip := range allIPs {
                if !seen[ip] && !isCloudflareIP(ip) {
                        seen[ip] = true
                        unique = append(unique, ip)
                }
        }
        return unique
}

func (h *HistoryModule) checkHackerTarget(ctx context.Context, domain string) []string {
        if err := h.limiter.Wait(ctx); err != nil {
                return nil
        }

        url := "https://api.hackertarget.com/hostsearch/?q=" + domain
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        resp, err := h.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        ipRegex := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

        var ips []string
        for _, line := range strings.Split(string(body), "\n") {
                if parts := strings.Split(line, ","); len(parts) >= 2 {
                        ip := strings.TrimSpace(parts[1])
                        if ipRegex.MatchString(ip) {
                                ips = append(ips, ip)
                        }
                }
        }
        return ips
}

func (h *HistoryModule) checkAlienVault(ctx context.Context, domain string) []string {
        if err := h.limiter.Wait(ctx); err != nil {
                return nil
        }

        url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := h.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)

        type passiveDNS struct {
                PassiveDNS []struct {
                        Address string `json:"address"`
                } `json:"passive_dns"`
        }

        var result passiveDNS
        if json.Unmarshal(body, &result) != nil {
                return nil
        }

        ipRegex := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
        var ips []string
        for _, entry := range result.PassiveDNS {
                if ipRegex.MatchString(entry.Address) {
                        ips = append(ips, entry.Address)
                }
        }
        return ips
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRIMEFLARE MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type CrimeFlareModule struct {
        db      map[string]string
        loaded  bool
        mu      sync.RWMutex
        client  *http.Client
}

func newCrimeFlare(timeout time.Duration) *CrimeFlareModule {
        return &CrimeFlareModule{
                db:     make(map[string]string),
                client: &http.Client{Timeout: timeout * 2},
        }
}

func (c *CrimeFlareModule) loadDB(ctx context.Context) {
        c.mu.Lock()
        defer c.mu.Unlock()
        if c.loaded {
                return
        }

        url := "https://cf.ozeliurs.com/ipout"
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := c.client.Do(req)
        if err != nil {
                return
        }
        defer resp.Body.Close()

        scanner := bufio.NewScanner(resp.Body)
        for scanner.Scan() {
                line := scanner.Text()
                parts := strings.Fields(line)
                if len(parts) >= 2 {
                        domain := strings.ToLower(parts[0])
                        ip := parts[1]
                        c.db[domain] = ip
                }
        }
        c.loaded = true
}

func (c *CrimeFlareModule) lookup(domain string) string {
        c.mu.RLock()
        defer c.mu.RUnlock()
        domain = strings.ToLower(domain)
        if ip, ok := c.db[domain]; ok {
                return ip
        }
        return ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// VIEWDNS MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type ViewDNSModule struct {
        client  *http.Client
        limiter *rate.Limiter
}

func newViewDNS(timeout time.Duration, rateLimit float64) *ViewDNSModule {
        return &ViewDNSModule{
                client:  &http.Client{Timeout: timeout},
                limiter: rate.NewLimiter(rate.Limit(rateLimit/3), 1),
        }
}

func (v *ViewDNSModule) getHistoricalIPs(ctx context.Context, domain string) []string {
        // Create a shorter timeout context for ViewDNS (it can be slow)
        shortCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
        defer cancel()

        if err := v.limiter.Wait(shortCtx); err != nil {
                return nil
        }

        url := fmt.Sprintf("https://viewdns.info/iphistory/?domain=%s", domain)
        req, _ := http.NewRequestWithContext(shortCtx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0")
        req.Header.Set("Accept", "text/html,application/xhtml+xml")

        resp, err := v.client.Do(req)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
        content := string(body)

        ipRegex := regexp.MustCompile(`<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>`)
        matches := ipRegex.FindAllStringSubmatch(content, -1)

        seen := make(map[string]bool)
        var ips []string
        for _, m := range matches {
                if len(m) > 1 && !seen[m[1]] && !isCloudflareIP(m[1]) {
                        seen[m[1]] = true
                        ips = append(ips, m[1])
                }
        }
        return ips
}

// ═══════════════════════════════════════════════════════════════════════════════
// FAVICON HASH MODULE
// ═══════════════════════════════════════════════════════════════════════════════

type FaviconModule struct {
        client *http.Client
}

func newFavicon(timeout time.Duration) *FaviconModule {
        return &FaviconModule{
                client: &http.Client{
                        Timeout: timeout,
                        Transport: &http.Transport{
                                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                        },
                },
        }
}

func (f *FaviconModule) getFaviconHash(ctx context.Context, domain string) string {
        urls := []string{
                fmt.Sprintf("https://%s/favicon.ico", domain),
                fmt.Sprintf("http://%s/favicon.ico", domain),
        }

        for _, url := range urls {
                req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
                req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

                resp, err := f.client.Do(req)
                if err != nil {
                        continue
                }

                if resp.StatusCode == 200 {
                        body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
                        resp.Body.Close()

                        if len(body) > 0 {
                                b64 := base64.StdEncoding.EncodeToString(body)
                                hash := md5.Sum([]byte(b64))
                                return fmt.Sprintf("%x", hash)
                        }
                }
                resp.Body.Close()
        }
        return ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// ORIGIN VERIFIER
// ═══════════════════════════════════════════════════════════════════════════════

type Verifier struct {
        client *http.Client
}

func newVerifier(timeout time.Duration) *Verifier {
        return &Verifier{
                client: &http.Client{
                        Timeout: timeout,
                        Transport: &http.Transport{
                                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                        },
                        CheckRedirect: func(req *http.Request, via []*http.Request) error {
                                if len(via) >= 3 {
                                        return http.ErrUseLastResponse
                                }
                                return nil
                        },
                },
        }
}

func (v *Verifier) getReference(ctx context.Context, domain string) (string, string) {
        req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+domain, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

        resp, err := v.client.Do(req)
        if err != nil {
                return "", ""
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
        content := string(body)

        titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
        title := ""
        if m := titleRegex.FindStringSubmatch(content); len(m) > 1 {
                title = strings.TrimSpace(m[1])
        }
        return content, title
}

func (v *Verifier) testOrigin(ctx context.Context, ip, domain, refContent, refTitle string) VerifiedOrigin {
        result := VerifiedOrigin{IP: ip}

        // Method 1: Check SSL certificate for domain
        if v.checkSSLCert(ip, domain) {
                result.Confidence = 0.85
                result.Method = "ssl_cert_match"
                return result
        }

        // Method 2: Host header injection (HTTPS then HTTP)
        for _, scheme := range []string{"https", "http"} {
                req, _ := http.NewRequestWithContext(ctx, "GET", scheme+"://"+ip+"/", nil)
                req.Header.Set("Host", domain)
                req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

                resp, err := v.client.Do(req)
                if err != nil {
                        continue
                }

                body, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
                resp.Body.Close()

                result.StatusCode = resp.StatusCode
                result.Method = scheme + "_host_header"

                // Accept 200, 301, 302 as valid responses
                if resp.StatusCode >= 200 && resp.StatusCode < 400 {
                        result.Confidence = 0.4
                        content := string(body)

                        // Check title match
                        titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
                        if m := titleRegex.FindStringSubmatch(content); len(m) > 1 {
                                if strings.EqualFold(strings.TrimSpace(m[1]), refTitle) {
                                        result.Confidence += 0.35
                                }
                        }

                        // Check domain mentioned in response
                        if strings.Contains(strings.ToLower(content), strings.ToLower(domain)) {
                                result.Confidence += 0.1
                        }

                        // Check content similarity
                        if sim := similarity(content, refContent); sim > 0.6 {
                                result.Confidence = sim
                        }

                        // Check redirect location contains domain
                        if loc := resp.Header.Get("Location"); loc != "" {
                                if strings.Contains(loc, domain) {
                                        result.Confidence += 0.2
                                }
                        }

                        if result.Confidence > 0.3 {
                                break
                        }
                }
        }

        // Method 3: Direct IP request (no Host header) - lower confidence
        if result.Confidence < 0.3 {
                req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+ip+"/", nil)
                req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
                if resp, err := v.client.Do(req); err == nil {
                        body, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
                        resp.Body.Close()
                        content := string(body)
                        if strings.Contains(strings.ToLower(content), strings.ToLower(domain)) {
                                result.Confidence = 0.35
                                result.Method = "domain_in_content"
                                result.StatusCode = resp.StatusCode
                        }
                }
        }

        return result
}

func (v *Verifier) checkSSLCert(ip, domain string) bool {
        conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ip+":443", &tls.Config{
                InsecureSkipVerify: true,
        })
        if err != nil {
                return false
        }
        defer conn.Close()

        certs := conn.ConnectionState().PeerCertificates
        if len(certs) == 0 {
                return false
        }

        cert := certs[0]
        // Check if domain matches cert CN or SANs
        if strings.EqualFold(cert.Subject.CommonName, domain) {
                return true
        }
        for _, san := range cert.DNSNames {
                if strings.EqualFold(san, domain) || (strings.HasPrefix(san, "*.") && strings.HasSuffix(domain, san[1:])) {
                        return true
                }
        }
        return false
}

func similarity(s1, s2 string) float64 {
        if len(s1) == 0 || len(s2) == 0 {
                return 0
        }
        if len(s1) > 3000 {
                s1 = s1[:3000]
        }
        if len(s2) > 3000 {
                s2 = s2[:3000]
        }

        w1 := strings.Fields(strings.ToLower(s1))
        w2 := strings.Fields(strings.ToLower(s2))

        set := make(map[string]bool)
        for _, w := range w1 {
                set[w] = true
        }
        common := 0
        for _, w := range w2 {
                if set[w] {
                        common++
                }
        }
        if len(w1)+len(w2) == 0 {
                return 0
        }
        return float64(2*common) / float64(len(w1)+len(w2))
}

func (v *Verifier) verifyCandidates(ctx context.Context, domain string, candidates []string) []VerifiedOrigin {
        if len(candidates) == 0 {
                return nil
        }

        refContent, refTitle := v.getReference(ctx, domain)

        var results []VerifiedOrigin
        var mu sync.Mutex
        var wg sync.WaitGroup

        jobs := make(chan string, len(candidates))
        for _, ip := range candidates {
                jobs <- ip
        }
        close(jobs)

        workers := 5
        if workers > len(candidates) {
                workers = len(candidates)
        }

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for ip := range jobs {
                                r := v.testOrigin(ctx, ip, domain, refContent, refTitle)
                                if r.Confidence > 0.3 {
                                        mu.Lock()
                                        results = append(results, r)
                                        mu.Unlock()
                                }
                        }
                }()
        }
        wg.Wait()
        return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

type Scanner struct {
        config         *Config
        dns            *DNSResolver
        crtsh          *CrtshModule
        wayback        *WaybackModule
        rapidDNS       *RapidDNSModule
        subCenter      *SubdomainCenterModule
        threatCrowd    *ThreatCrowdModule
        history        *HistoryModule
        crimeflare     *CrimeFlareModule
        viewdns        *ViewDNSModule
        favicon        *FaviconModule
        verifier       *Verifier
        found          int64
}

func newScanner(cfg *Config) *Scanner {
        timeout := time.Duration(cfg.Timeout) * time.Second
        return &Scanner{
                config:      cfg,
                dns:         newDNSResolver(timeout),
                crtsh:       newCrtsh(timeout, cfg.RateLimit),
                wayback:     newWayback(timeout, cfg.RateLimit/2),
                rapidDNS:    newRapidDNS(timeout, cfg.RateLimit/2),
                subCenter:   newSubdomainCenter(timeout),
                threatCrowd: newThreatCrowd(timeout),
                history:     newHistory(timeout, cfg.RateLimit),
                crimeflare:  newCrimeFlare(timeout),
                viewdns:     newViewDNS(timeout, cfg.RateLimit),
                favicon:     newFavicon(timeout),
                verifier:    newVerifier(timeout),
        }
}

func (s *Scanner) scanDomain(ctx context.Context, domain string) ScanResult {
        start := time.Now()
        result := ScanResult{Domain: domain}
        candidateSet := make(map[string]bool)
        allSubs := make(map[string]bool)

        ips, isCF, err := s.dns.resolve(domain)
        if err != nil {
                result.Error = err.Error()
                return result
        }
        result.IsCloudflare = isCF
        result.CloudflareIPs = ips

        if !isCF {
                for _, ip := range ips {
                        if !isCloudflareIP(ip) {
                                candidateSet[ip] = true
                        }
                }
        }

        subs, _ := s.crtsh.getSubdomains(ctx, domain)
        for _, sub := range subs {
                allSubs[sub] = true
        }

        wbSubs := s.wayback.getSubdomains(ctx, domain)
        result.WaybackSubs = wbSubs
        for _, sub := range wbSubs {
                allSubs[sub] = true
        }

        rdSubs := s.rapidDNS.getSubdomains(ctx, domain)
        for _, sub := range rdSubs {
                allSubs[sub] = true
        }

        // subdomain.center (comprehensive free API)
        scSubs := s.subCenter.getSubdomains(ctx, domain)
        for _, sub := range scSubs {
                allSubs[sub] = true
        }

        // ThreatCrowd subdomains + historical IPs
        tcSubs := s.threatCrowd.getSubdomains(ctx, domain)
        for _, sub := range tcSubs {
                allSubs[sub] = true
        }
        tcIPs := s.threatCrowd.getIPs(ctx, domain)
        result.ThreatCrowdIPs = tcIPs
        for _, ip := range tcIPs {
                candidateSet[ip] = true
        }

        // Common subdomains bruteforce
        for _, prefix := range commonSubdomains {
                allSubs[prefix+"."+domain] = true
        }

        result.SubdomainsFound = len(allSubs)

        var subList []string
        for sub := range allSubs {
                subList = append(subList, sub)
        }
        subResults := s.dns.resolveBulk(subList, 30)
        for _, ips := range subResults {
                for _, ip := range ips {
                        candidateSet[ip] = true
                }
        }

        mxIPs := s.dns.getMXIPs(domain)
        result.MXIPs = mxIPs
        for _, ip := range mxIPs {
                candidateSet[ip] = true
        }

        spfIPs := s.dns.getSPFIPs(domain)
        result.SPFIPs = spfIPs
        for _, ip := range spfIPs {
                candidateSet[ip] = true
        }

        histIPs := s.history.getHistoricalIPs(ctx, domain)
        result.HistoricalIPs = histIPs
        for _, ip := range histIPs {
                candidateSet[ip] = true
        }

        // CrimeFlare lookup
        cfIP := s.crimeflare.lookup(domain)
        if cfIP != "" {
                result.CrimeFlareIP = cfIP
                candidateSet[cfIP] = true
        }

        // ViewDNS historical IPs
        vdIPs := s.viewdns.getHistoricalIPs(ctx, domain)
        result.ViewDNSIPs = vdIPs
        for _, ip := range vdIPs {
                candidateSet[ip] = true
        }

        // IPv6 lookup
        ipv6 := s.dns.getIPv6(domain)
        result.IPv6Addrs = ipv6

        result.FaviconHash = s.favicon.getFaviconHash(ctx, domain)

        var candidates []string
        for ip := range candidateSet {
                candidates = append(candidates, ip)
        }
        result.CandidateIPs = candidates

        if len(candidates) > 0 {
                result.VerifiedOrigins = s.verifier.verifyCandidates(ctx, domain, candidates)
        }

        result.ScanTime = time.Since(start).Seconds()
        return result
}

func (s *Scanner) scanDomains(ctx context.Context, domains []string) []ScanResult {
        var results []ScanResult
        var mu sync.Mutex
        var wg sync.WaitGroup
        var printMu sync.Mutex

        jobs := make(chan string, len(domains))
        for _, d := range domains {
                jobs <- d
        }
        close(jobs)

        workers := s.config.Workers
        if workers > len(domains) {
                workers = len(domains)
        }

        total := len(domains)
        var scanned int64

        for i := 0; i < workers; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for domain := range jobs {
                                select {
                                case <-ctx.Done():
                                        return
                                default:
                                }

                                result := s.scanDomain(ctx, domain)

                                mu.Lock()
                                results = append(results, result)
                                mu.Unlock()

                                n := atomic.AddInt64(&scanned, 1)
                                if len(result.VerifiedOrigins) > 0 {
                                        atomic.AddInt64(&s.found, 1)
                                }

                                if s.config.Verbose {
                                        printMu.Lock()
                                        s.printResult(result, int(n), total)
                                        printMu.Unlock()
                                }
                        }
                }()
        }

        wg.Wait()
        return results
}

func (s *Scanner) printResult(r ScanResult, n, total int) {
        pct := float64(n) / float64(total) * 100
        bar := progressBar(int(pct), 20)

        cfStatus := nordicGreen("direct")
        if r.IsCloudflare {
                cfStatus = nordicAccent("CF")
        }

        originStr := nordicDim("—")
        if len(r.VerifiedOrigins) > 0 {
                best := r.VerifiedOrigins[0]
                originStr = fmt.Sprintf("%s%s%s %s%.0f%%%s", green, best.IP, reset, dimGray, best.Confidence*100, reset)
        } else if len(r.CandidateIPs) > 0 && !r.IsCloudflare {
                // Show first candidate as unverified for non-CF domains
                originStr = fmt.Sprintf("%s%s%s %s?%s", yellow, r.CandidateIPs[0], reset, dimGray, reset)
        }

        methodsUsed := []string{}
        if r.SubdomainsFound > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("subs:%d", r.SubdomainsFound))
        }
        if len(r.MXIPs) > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("mx:%d", len(r.MXIPs)))
        }
        if len(r.SPFIPs) > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("spf:%d", len(r.SPFIPs)))
        }
        if len(r.HistoricalIPs) > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("hist:%d", len(r.HistoricalIPs)))
        }
        if len(r.WaybackSubs) > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("wb:%d", len(r.WaybackSubs)))
        }
        if r.CrimeFlareIP != "" {
                methodsUsed = append(methodsUsed, yellow+"cf!"+reset)
        }
        if len(r.ViewDNSIPs) > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("vd:%d", len(r.ViewDNSIPs)))
        }
        if len(r.ThreatCrowdIPs) > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("tc:%d", len(r.ThreatCrowdIPs)))
        }
        if len(r.IPv6Addrs) > 0 {
                methodsUsed = append(methodsUsed, fmt.Sprintf("v6:%d", len(r.IPv6Addrs)))
        }

        methods := nordicDim(strings.Join(methodsUsed, " "))

        fmt.Printf("  %s%s%s %3.0f%% %s%-28s%s %s %s%-18s%s %s%d%s %s\n",
                dimGray, bar, reset,
                pct,
                white, truncate(r.Domain, 28), reset,
                cfStatus,
                reset, originStr, reset,
                dimGray, len(r.CandidateIPs), reset,
                methods)
}

func progressBar(percent, width int) string {
        filled := percent * width / 100
        if filled > width {
                filled = width
        }
        bar := strings.Repeat("━", filled) + strings.Repeat("─", width-filled)
        return cyan + bar + reset
}

// ═══════════════════════════════════════════════════════════════════════════════
// CSV OUTPUT
// ═══════════════════════════════════════════════════════════════════════════════

func saveCSV(results []ScanResult, filepath string) error {
        file, err := os.Create(filepath)
        if err != nil {
                return err
        }
        defer file.Close()

        writer := csv.NewWriter(file)
        defer writer.Flush()

        header := []string{"domain", "cloudflare", "subdomains", "candidates", "origin_ip", "confidence", "method", "crimeflare_ip", "viewdns_ips", "threatcrowd_ips", "mx_ips", "spf_ips", "historical_ips", "ipv6", "favicon_hash", "scan_time"}
        writer.Write(header)

        for _, r := range results {
                originIP := ""
                confidence := ""
                method := ""
                if len(r.VerifiedOrigins) > 0 {
                        originIP = r.VerifiedOrigins[0].IP
                        confidence = fmt.Sprintf("%.0f%%", r.VerifiedOrigins[0].Confidence*100)
                        method = r.VerifiedOrigins[0].Method
                }

                row := []string{
                        r.Domain,
                        fmt.Sprintf("%v", r.IsCloudflare),
                        fmt.Sprintf("%d", r.SubdomainsFound),
                        fmt.Sprintf("%d", len(r.CandidateIPs)),
                        originIP,
                        confidence,
                        method,
                        r.CrimeFlareIP,
                        strings.Join(r.ViewDNSIPs, ";"),
                        strings.Join(r.ThreatCrowdIPs, ";"),
                        strings.Join(r.MXIPs, ";"),
                        strings.Join(r.SPFIPs, ";"),
                        strings.Join(r.HistoricalIPs, ";"),
                        strings.Join(r.IPv6Addrs, ";"),
                        r.FaviconHash,
                        fmt.Sprintf("%.1f", r.ScanTime),
                }
                writer.Write(row)
        }

        return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════════

func printBanner() {
        banner := `
` + white + `    ╻┏━┓┏━┓┏━╸┏━╸┏━┓┏┓╻` + reset + `
` + gray + `    ┃┣━┛┣┳┛┣╸ ┃  ┃ ┃┃┗┫` + reset + `
` + dimGray + `    ╹╹  ╹┗╸┗━╸┗━╸┗━┛╹ ╹` + reset + `
` + dimGray + `    Origin IP Discovery` + reset + `
`
        fmt.Print(banner)
}

func main() {
        domain := flag.String("d", "", "Single domain to scan")
        file := flag.String("f", "", "File with domains (one per line)")
        workers := flag.Int("w", 50, "Number of concurrent workers")
        timeout := flag.Int("t", 10, "Request timeout in seconds")
        output := flag.String("o", "", "Output file (supports .csv and .json)")
        quiet := flag.Bool("q", false, "Quiet mode")
        flag.Parse()

        if *domain == "" && *file == "" {
                printBanner()
                fmt.Println()
                fmt.Println(nordic("  Usage:"))
                fmt.Println(nordicDim("    iprecon -d domain.com"))
                fmt.Println(nordicDim("    iprecon -f domains.txt -w 100 -o results.csv"))
                fmt.Println()
                fmt.Println(nordic("  Methods (15 free sources):"))
                fmt.Println(nordicDim("    crt.sh, Wayback, RapidDNS, subdomain.center, ThreatCrowd"))
                fmt.Println(nordicDim("    CrimeFlare, ViewDNS, MX, SPF, DNS History (HackerTarget+AlienVault)"))
                fmt.Println(nordicDim("    Common subdomains bruteforce, IPv6, Favicon hash, Host header verify"))
                fmt.Println()
                fmt.Println(nordic("  Options:"))
                flag.PrintDefaults()
                os.Exit(1)
        }

        var domains []string
        if *domain != "" {
                domains = []string{*domain}
        } else {
                f, err := os.Open(*file)
                if err != nil {
                        fmt.Printf("%sError: %v%s\n", yellow, err, reset)
                        os.Exit(1)
                }
                scanner := bufio.NewScanner(f)
                for scanner.Scan() {
                        line := strings.TrimSpace(scanner.Text())
                        if line != "" && !strings.HasPrefix(line, "#") {
                                line = strings.TrimPrefix(line, "http://")
                                line = strings.TrimPrefix(line, "https://")
                                line = strings.Split(line, "/")[0]
                                domains = append(domains, line)
                        }
                }
                f.Close()
        }

        if !*quiet {
                printBanner()
                fmt.Println()
                fmt.Printf("%s  Domains: %s%d%s | Workers: %s%d%s\n\n",
                        dimGray, white, len(domains), dimGray, white, *workers, reset)
        }

        cfg := &Config{
                Workers:   *workers,
                Timeout:   *timeout,
                RateLimit: 10,
                Verbose:   !*quiet,
        }

        s := newScanner(cfg)

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
        go func() {
                <-sigChan
                fmt.Println("\n\n  Interrupted...")
                cancel()
        }()

        // Load CrimeFlare database
        if !*quiet {
                fmt.Printf("  %sLoading CrimeFlare database...%s", dimGray, reset)
        }
        s.crimeflare.loadDB(ctx)
        if !*quiet {
                fmt.Printf("\r  %sCrimeFlare: %s%d%s entries loaded%s\n\n", dimGray, white, len(s.crimeflare.db), dimGray, reset)
        }

        start := time.Now()
        results := s.scanDomains(ctx, domains)

        if !*quiet {
                fmt.Println()
                fmt.Println()

                var found, cf, totalSubs, totalCandidates int
                for _, r := range results {
                        if len(r.VerifiedOrigins) > 0 {
                                found++
                        }
                        if r.IsCloudflare {
                                cf++
                        }
                        totalSubs += r.SubdomainsFound
                        totalCandidates += len(r.CandidateIPs)
                }

                fmt.Println(nordicDim("  ─────────────────────────────────────"))
                fmt.Println(nordicBold("              STATISTICS               "))
                fmt.Println(nordicDim("  ─────────────────────────────────────"))
                fmt.Println()
                fmt.Printf("  %sTotal Domains:%s     %s%d%s\n", dimGray, reset, white, len(results), reset)
                fmt.Printf("  %sCloudflare:%s        %s%d%s %s(%.1f%%)%s\n", dimGray, reset, white, cf, reset, dimGray, float64(cf)/float64(len(results))*100, reset)
                fmt.Printf("  %sSubdomains:%s        %s%d%s\n", dimGray, reset, white, totalSubs, reset)
                fmt.Printf("  %sCandidates:%s        %s%d%s\n", dimGray, reset, white, totalCandidates, reset)
                fmt.Printf("  %sOrigins Found:%s     %s%d%s %s(%.1f%%)%s\n", dimGray, reset, green, found, reset, dimGray, float64(found)/float64(len(results))*100, reset)
                fmt.Printf("  %sTime:%s              %s%s%s\n", dimGray, reset, white, time.Since(start).Round(time.Second), reset)
                fmt.Println()

                if found > 0 {
                        fmt.Println(nordicDim("  ─────────────────────────────────────"))
                        fmt.Println(nordicBold("           DISCOVERED ORIGINS          "))
                        fmt.Println(nordicDim("  ─────────────────────────────────────"))
                        fmt.Println()
                        for _, r := range results {
                                for _, v := range r.VerifiedOrigins {
                                        fmt.Printf("  %s%s%s %s→%s %s%s%s %s(%.0f%%)%s\n",
                                                white, r.Domain, reset,
                                                dimGray, reset,
                                                green, v.IP, reset,
                                                dimGray, v.Confidence*100, reset)
                                }
                        }
                        fmt.Println()
                }
        }

        if *output != "" {
                if strings.HasSuffix(*output, ".csv") {
                        saveCSV(results, *output)
                } else {
                        data, _ := json.MarshalIndent(results, "", "  ")
                        os.WriteFile(*output, data, 0644)
                }
                fmt.Printf("  %sSaved:%s %s%s%s\n\n", dimGray, reset, white, *output, reset)
        }
}

func truncate(s string, max int) string {
        if len(s) <= max {
                return s + strings.Repeat(" ", max-len(s))
        }
        return s[:max-2] + ".."
}
