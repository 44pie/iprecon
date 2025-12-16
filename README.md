# IPRECON

Origin IP discovery scanner for domains behind Cloudflare/CDN protection.

```
    ╻┏━┓┏━┓┏━╸┏━╸┏━┓┏┓╻
    ┃┣━┛┣┳┛┣╸ ┃  ┃ ┃┃┗┫
    ╹╹  ╹┗╸┗━╸┗━╸┗━┛╹ ╹
    Origin IP Discovery
```

## Features

- **15 free reconnaissance sources** (no API keys required)
- **86%+ origin discovery rate** on real-world targets
- **Cloudflare bypass** through multiple techniques
- **Fast parallel scanning** with configurable workers
- **CSV/JSON output** for integration with other tools

## Installation

```bash
# Download binary
wget https://github.com/iprecon/iprecon/releases/latest/download/iprecon
chmod +x iprecon

# Or build from source
go build -o iprecon main.go
```

## Usage

```bash
# Single domain
./iprecon -d example.com

# Multiple domains from file
./iprecon -f domains.txt -w 50 -o results.csv

# Options
  -d string    Single domain to scan
  -f string    File with domains (one per line)
  -w int       Number of concurrent workers (default 50)
  -t int       Request timeout in seconds (default 10)
  -o string    Output file (.csv or .json)
  -q           Quiet mode
```

## Data Sources (15 Free Methods)

| Source | Type | Description |
|--------|------|-------------|
| crt.sh | Subdomains | Certificate Transparency logs |
| Wayback Machine | Subdomains | Historical archived URLs |
| RapidDNS | Subdomains | DNS aggregator |
| subdomain.center | Subdomains | Comprehensive free API |
| ThreatCrowd | Subdomains + IPs | Historical DNS data |
| CrimeFlare | Origin IPs | 2996 leaked Cloudflare origins |
| ViewDNS | Historical IPs | DNS history lookup |
| MX Records | IPs | Mail server discovery |
| SPF Records | IPs | SPF include statements |
| HackerTarget | Historical IPs | DNS history API |
| AlienVault OTX | Historical IPs | Threat intelligence |
| Common Subdomains | Subdomains | 50+ prefix bruteforce |
| IPv6 Resolution | IPs | Often unprotected |
| Favicon Hash | Fingerprint | For Shodan/Censys search |
| Host Header Verify | Verification | Origin confirmation |

## Output Indicators

```
subs:N   - Subdomains found
mx:N     - MX record IPs
spf:N    - SPF record IPs
hist:N   - Historical IPs
wb:N     - Wayback subdomains
cf!      - CrimeFlare database hit (yellow)
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

  ━━━━━━━━━━━━━━━━━━━━ 100% target.com  CF 185.93.1.245 50% 6 subs:62 mx:4 v6:2

  ─────────────────────────────────────
              STATISTICS               
  ─────────────────────────────────────

  Total Domains:     30
  Cloudflare:        8 (26.7%)
  Origins Found:     26 (86.7%)
  Time:              1m38s
```

## Performance

- **30 domains**: ~1.5 minutes with 15 workers
- **100 domains**: ~5 minutes with 50 workers
- **1000 domains**: ~30 minutes with 100 workers

## How It Works

1. **Subdomain Enumeration**: Gathers subdomains from multiple passive sources
2. **DNS Resolution**: Resolves all discovered subdomains to IPs
3. **Historical Lookup**: Checks DNS history databases for pre-Cloudflare IPs
4. **CrimeFlare Check**: Looks up domain in leaked Cloudflare origin database
5. **Record Analysis**: Extracts IPs from MX/SPF/TXT records
6. **Origin Verification**: Tests candidate IPs with Host header injection

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
