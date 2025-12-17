# IPRECON

Origin IP discovery scanner for domains behind Cloudflare/CDN protection.

```
    ╻┏━┓┏━┓┏━╸┏━╸┏━┓┏┓╻
    ┃┣━┛┣┳┛┣╸ ┃  ┃ ┃┃┗┫
    ╹╹  ╹┗╸┗━╸┗━╸┗━┛╹ ╹
    Origin IP Discovery
```

## Features

- **20+ free reconnaissance sources** (no API keys required)
- **86-100% origin discovery rate** on real-world targets
- **CDN/Cloud provider filtering** (Google, AWS, Azure, Fastly, Akamai)
- **Advanced verification** with SSL cert matching, content analysis, redirect detection
- **Fast parallel scanning** with configurable workers
- **ASN subnet expansion** for thorough discovery
- **CSV/JSON output** for integration with other tools

## Installation

```bash
# Download binary
wget https://github.com/44pie/iprecon/releases/latest/download/iprecon-linux-amd64
chmod +x iprecon-linux-amd64
mv iprecon-linux-amd64 iprecon

# Or build from source
go build -o iprecon main.go
```

## Usage

```bash
# Single domain
./iprecon -d example.com

# Multiple domains from file
./iprecon -f domains.txt -w 50 -o results.csv

# With ASN subnet expansion (more thorough)
./iprecon -f domains.txt -asn -o results.csv

# Options
  -d string    Single domain to scan
  -f string    File with domains (one per line)
  -w int       Number of concurrent workers (default 50)
  -t int       Request timeout in seconds (default 10)
  -o string    Output file (.csv or .json)
  -q           Quiet mode
  -asn         Enable ASN /24 subnet expansion
  -h           Show help
```

## Detection Methods (20+ Sources)

### Passive Reconnaissance (11 methods)

| # | Source | Type | Description |
|---|--------|------|-------------|
| 1 | crt.sh | Subdomains | Certificate Transparency logs |
| 2 | Wayback Machine | Subdomains | Historical archived URLs |
| 3 | RapidDNS | Subdomains | DNS aggregator |
| 4 | subdomain.center | Subdomains | Comprehensive free API |
| 5 | ThreatCrowd | Subdomains + IPs | Historical DNS data |
| 6 | Common Subdomains | Subdomains | 50+ prefix bruteforce |
| 7 | HackerTarget | Historical IPs | DNS history API |
| 8 | AlienVault OTX | Historical IPs | Threat intelligence |
| 9 | CrimeFlare | Origin IPs | 2996 leaked Cloudflare origins |
| 10 | ViewDNS | Historical IPs | DNS history lookup |
| 11 | MX/SPF Records | IPs | Mail server and SPF discovery |

### Active Reconnaissance (6 methods)

| # | Source | Type | Description |
|---|--------|------|-------------|
| 12 | IPv6 Resolution | IPs | Often unprotected by CDN |
| 13 | PTR Records | Reverse DNS | Hostname discovery |
| 14 | HTML/JS Parsing | IPs | Extract IPs from page content |
| 15 | robots.txt/sitemap | IPs | Parse service files for hosts |
| 16 | Error Page Trigger | IPs | Force server error responses |
| 17 | AXFR Zone Transfer | DNS Zone | Attempt full zone transfer |

### Verification & Analysis (5 methods)

| # | Method | Description |
|---|--------|-------------|
| 18 | Host Header Verify | Test origin with domain header |
| 19 | SSL Cert Match | Verify CN/SAN matches domain |
| 20 | Content Similarity | Compare with reference content |
| 21 | Domain-in-Content | Search for domain in HTML |
| 22 | Redirect Analysis | Follow redirects to confirm |

### Optional: ASN Expansion (-asn flag)

| # | Method | Description |
|---|--------|-------------|
| 23 | /24 Subnet Scan | Scan 256 IPs around verified origin |
| 24 | Port Check | Quick 443/80 port verification |
| 25 | Neighbor Verify | Full verification on open ports |

## CDN/Cloud Provider Filtering

IPRECON automatically filters out IPs belonging to major CDN and cloud providers to reduce false positives:

- **Cloudflare** - All known ranges
- **Google** - 142.250.x.x, 172.253.x.x, 64.233.x.x, etc.
- **AWS** - 52.x.x.x, 54.x.x.x, 35.x.x.x
- **Azure** - 13.x.x.x, 40.x.x.x, 20.x.x.x
- **Fastly, Akamai, DigitalOcean**

## Confidence Scoring

Each verified origin receives a confidence score based on:

| Signal | Weight |
|--------|--------|
| HTTP 200-399 response | +40% |
| SSL cert matches domain | +30% |
| Domain found in HTML | +20% |
| Content similarity | +10% |
| Correct redirect | +10% |

**Threshold**: Only results with >40% confidence are displayed.

## Output Indicators

```
subs:N   - Subdomains found
mx:N     - MX record IPs
spf:N    - SPF record IPs
hist:N   - Historical IPs
wb:N     - Wayback subdomains
cf!      - CrimeFlare database hit
vd:N     - ViewDNS historical IPs
tc:N     - ThreatCrowd IPs
v6:N     - IPv6 addresses found
```

## CSV Output Format

```csv
domain,cloudflare,subdomains,candidates,origin_ip,confidence,method,crimeflare_ip,viewdns_ips,threatcrowd_ips,mx_ips,spf_ips,historical_ips,ipv6,favicon_hash,scan_time
```

## Example Output

```
  Domains: 30 | Workers: 15
  CrimeFlare: 2996 entries loaded

  ━━━━━━━━━━━━━━━━━━━━ 100% target.com  CF 185.93.1.245 100% subs:62 mx:4 v6:2

  ─────────────────────────────────────
              STATISTICS               
  ─────────────────────────────────────

  Total Domains:     30
  Cloudflare:        8 (26.7%)
  Origins Found:     26 (86.7%)
  Time:              1m38s

  ─────────────────────────────────────
           DISCOVERED ORIGINS          
  ─────────────────────────────────────

  target.com → 185.93.1.245 (100%)
```

## Performance

- **30 domains**: ~1.5 minutes with 15 workers
- **100 domains**: ~5 minutes with 50 workers
- **1000 domains**: ~30 minutes with 100 workers

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                      IPRECON Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│  1. DNS Resolution      → Check if behind Cloudflare         │
│  2. Passive Recon       → 11 sources (crt.sh, Wayback, etc.) │
│  3. Active Recon        → 6 sources (IPv6, PTR, HTML parse)  │
│  4. CDN Filtering       → Remove Google/AWS/Azure/etc. IPs   │
│  5. Verification        → 5 checks (SSL, content, headers)   │
│  6. ASN Expansion       → Optional /24 subnet scan           │
│  7. Confidence Scoring  → Rank results by verification       │
└─────────────────────────────────────────────────────────────┘
```

## Favicon Hash Usage

IPRECON calculates favicon hashes for manual Shodan/Censys searches:

```bash
# Search in Shodan
http.favicon.hash:-1234567890

# Search in Censys  
services.http.response.favicons.md5_hash:"abc123..."
```

## Legal Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning targets you don't own.

## License

MIT License
