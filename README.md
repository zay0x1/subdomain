# SubEnum

**Comprehensive subdomain enumeration tool combining passive discovery, active brute-forcing, permutation generation, and live HTTP probing into a single async-powered CLI.**

No API keys required — only publicly available data sources.

---

## Features

### Passive Discovery
- **Certificate Transparency** — queries [crt.sh](https://crt.sh) for historically issued certificates
- **DNS Record Mining** — parses MX, NS, SOA, TXT (SPF/DKIM/DMARC) records for referenced subdomains

### Active Discovery
- **DNS Brute-Force** — async resolution via `aiodns` with a built-in wordlist of 1,450+ common subdomain prefixes
- **Wildcard Detection** — fires random subdomain probes to identify and filter wildcard DNS responses before they flood results
- **Recursive Enumeration** — every discovered subdomain becomes a new base domain for further bruting (configurable depth)

### Permutation Engine
Mutates discovered subdomains to find related hosts:
- Prepend/append common words (`dev-`, `-staging`, `api.`, etc.)
- Insert numbers (`host1`, `host-2`)
- Swap dashes and dots (`web-app` ↔ `web.app`)

### Output
- Deduplicated results with IPs, CNAME chains, and source tags
- Clean terminal table
- Export to **JSON** and **CSV**
- Optional HTTP status codes via `--http-check`

### Reliability
- Retry logic with exponential backoff on DNS timeouts
- Token-bucket rate limiter (default 500 qps)
- Configurable concurrency (default 100 async tasks)
- Progress bars via `tqdm`
- Verbose (`-v`) and quiet (`-q`) modes

---

## Installation

```bash
git clone https://github.com/youruser/subenum.git
cd subenum
pip install -r requirements.txt
```

### Requirements

Python 3.10+ and three packages:

```
aiodns
aiohttp
tqdm
```

Or install directly:

```bash
pip install aiodns aiohttp tqdm
```

---

## Usage

```bash
python subenum.py <domain> [options]
```

### Quick Examples

```bash
# Full scan with all phases
python subenum.py example.com

# Export results to JSON and CSV
python subenum.py example.com -oJ results.json -oC results.csv

# Include HTTP status code probing
python subenum.py example.com --http-check

# Recursive enumeration (depth 3)
python subenum.py example.com -r --recursive-depth 3

# Passive only (no brute-force, no permutations)
python subenum.py example.com --no-brute --no-permutation

# Custom wordlist with higher concurrency
python subenum.py example.com -w wordlist.txt -c 200

# Use specific DNS resolvers
python subenum.py example.com --resolvers 8.8.8.8,1.1.1.1

# Quiet mode (table output only)
python subenum.py example.com -q

# Verbose mode (debug logging)
python subenum.py example.com -v
```

---

## Options Reference

| Flag | Description | Default |
|---|---|---|
| `domain` | Target domain (positional) | *required* |
| `--no-passive` | Skip crt.sh and DNS record mining | off |
| `--no-brute` | Skip DNS brute-force | off |
| `-w`, `--wordlist` | Custom wordlist file (one word per line) | built-in (1,450+) |
| `-c`, `--concurrency` | Number of concurrent async tasks | `100` |
| `--retries` | DNS query retry count | `3` |
| `--timeout` | DNS query timeout (seconds) | `5.0` |
| `--rate-limit` | Max DNS queries per second | `500` |
| `--resolvers` | Comma-separated nameserver IPs | public DNS pool |
| `-r`, `--recursive` | Recursively enumerate discovered subdomains | off |
| `--recursive-depth` | Maximum recursion depth | `2` |
| `--no-permutation` | Skip the permutation engine | off |
| `--http-check` | Probe each host for HTTP/HTTPS status codes | off |
| `-oJ`, `--output-json` | Export results to a JSON file | — |
| `-oC`, `--output-csv` | Export results to a CSV file | — |
| `-v`, `--verbose` | Enable debug logging to stderr | off |
| `-q`, `--quiet` | Suppress everything except the results table | off |

---

## How It Works

SubEnum runs six sequential phases:

```
Phase 1 — Passive Discovery
  ├── Query crt.sh Certificate Transparency logs
  └── Mine MX / NS / SOA / TXT records

Phase 2 — Wildcard Detection
  └── Probe 12 random subdomains; flag IPs that appear in ≥75%

Phase 3 — Active Brute-Force
  ├── Resolve wordlist against target domain
  ├── Filter wildcard false positives
  └── (Optional) Recurse into discovered subdomains

Phase 4 — Permutation Engine
  └── Mutate discovered names → resolve candidates

Phase 5 — Passive Resolution
  └── Resolve IPs / CNAMEs for passive-only entries

Phase 6 — HTTP Live Check (optional)
  └── GET request to each host over HTTPS then HTTP
```

All results are deduplicated by FQDN and tagged with their discovery source.

---

## Output Formats

### Terminal Table

```
  ──────────────────────────────────────────────────────────────────────
  Subdomain          IP(s)              CNAME              Source
  ──────────────────────────────────────────────────────────────────────
  api.example.com    93.184.216.34                         brute, crt.sh
  dev.example.com    93.184.216.35      dev.cdn.example…   permutation
  mail.example.com   93.184.216.36                         dns-records
  ──────────────────────────────────────────────────────────────────────
  Total: 3 unique subdomains
```

### JSON (`-oJ`)

```json
[
  {
    "subdomain": "api.example.com",
    "ips": ["93.184.216.34"],
    "cname_chain": [],
    "sources": ["brute", "crt.sh"],
    "http_status": 200,
    "http_redirect": null
  }
]
```

### CSV (`-oC`)

```
subdomain,ips,cname_chain,sources,http_status,http_redirect
api.example.com,93.184.216.34,,brute|crt.sh,200,
```

---

## Built-in Wordlist

The tool ships with a curated wordlist of **1,450+ common subdomain prefixes** covering:

- Infrastructure (`ns`, `mx`, `dns`, `vpn`, `proxy`, `gateway`)
- Development lifecycle (`dev`, `staging`, `uat`, `qa`, `prod`, `beta`)
- Applications (`api`, `app`, `portal`, `dashboard`, `admin`, `cms`)
- Services (`mail`, `ftp`, `ssh`, `db`, `cdn`, `cache`, `queue`)
- Cloud & DevOps (`cloud`, `docker`, `k8s`, `jenkins`, `monitor`)
- Short labels (`a`–`zz`) for comprehensive coverage

Supply your own with `-w path/to/wordlist.txt` (one entry per line).

---

## Performance Tuning

| Scenario | Recommended flags |
|---|---|
| Fast scan on reliable network | `-c 300 --rate-limit 1000` |
| Stealth / low-bandwidth | `-c 20 --rate-limit 50 --timeout 10` |
| Large custom wordlist | `-c 200 --rate-limit 800` |
| Deep recursive dive | `-r --recursive-depth 4 -c 150` |
| Passive recon only | `--no-brute --no-permutation` |

The default settings (`-c 100`, `--rate-limit 500`) are a safe balance for most targets.

---

## Troubleshooting

**"Missing required packages"** — Install dependencies: `pip install aiodns aiohttp tqdm`

**Wildcard flooding results** — This is handled automatically. The tool probes 12 random subdomains before bruting; if ≥75% resolve to the same IP, those IPs are filtered. If you still see noise, the domain may have partial wildcards on specific subzones.

**Timeouts on large wordlists** — Increase `--timeout` and decrease `--concurrency`. Some resolvers throttle high-volume clients.

**Empty crt.sh results** — The target may not have publicly logged certificates, or crt.sh may be rate-limiting. Results from other phases will still populate.

---

## Disclaimer

This tool is intended for **authorized security testing and reconnaissance only**. Always obtain written permission before enumerating subdomains of domains you do not own. Unauthorized scanning may violate laws and terms of service.

---

## License

MIT
