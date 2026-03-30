<div align="center">

# 🔍 SubRecon

**Comprehensive Subdomain Enumeration Tool**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-PEP8-black.svg)](https://peps.python.org/pep-0008/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Issues](https://img.shields.io/github/issues/yourusername/subrecon)](https://github.com/yourusername/subrecon/issues)

*Combine passive intelligence, active brute-force, and smart permutations into a single, blazing-fast CLI tool. No API keys required.*

[Installation](#-installation) •
[Quick Start](#-quick-start) •
[Features](#-features) •
[Usage](#-usage) •
[Architecture](#-architecture) •
[Contributing](#-contributing)

---

</div>

## ✨ Features

| Category | Capability | Details |
|----------|-----------|---------|
| 🕵️ **Passive** | Certificate Transparency | Query [crt.sh](https://crt.sh) for historically issued certificates |
| 🕵️ **Passive** | DNS Record Mining | Extract subdomains from MX, NS, SOA, TXT (SPF), CNAME records |
| ⚡ **Active** | Async DNS Brute-Force | Concurrent resolution via `asyncio` + `aiodns` (configurable up to 500+ tasks) |
| ⚡ **Active** | Wildcard Detection | Automatic wildcard DNS detection prevents false-positive flooding |
| ⚡ **Active** | Recursive Enumeration | Discovered subdomains become new base domains for deeper bruting |
| 🧬 **Smart** | Permutation Engine | Prepend/append words, insert numbers, swap dashes on discovered subs |
| 🌐 **Validation** | HTTP Live Check | Optional status code + redirect detection on all results |
| 📊 **Output** | Multi-Format Export | Terminal table, JSON (structured), CSV — all deduplicated |
| 🛡️ **Reliability** | Production-Grade | Retry logic, rate limiting, progress bars, verbose/quiet modes |

## 📦 Installation

### From Source (Recommended)

```bash
git clone https://github.com/yourusername/subrecon.git
cd subrecon
pip install -e ".[dev]"
```

### Quick Install

```bash
pip install -r requirements.txt
python -m subrecon -d example.com
```

### Requirements

- **Python 3.8+**
- Dependencies: `aiodns`, `aiohttp`, `tqdm`

## 🚀 Quick Start

```bash
# Basic scan
subrecon -d example.com

# Full scan with HTTP checks + export
subrecon -d example.com --live-check -o results -v

# High-performance recursive scan
subrecon -d example.com -c 200 --recursive --depth 3
```

## 📖 Usage

```
usage: subrecon [-h] -d DOMAIN [-w WORDLIST] [--no-crtsh] [--no-permutations]
                [--max-permutations N] [--recursive] [--depth N]
                [--live-check] [-c N] [--rate-limit N] [--timeout N]
                [--retries N] [--nameservers NS] [-o FILE] [--json-only]
                [--csv-only] [--no-table] [-v] [-q] [--version]
```

### Core Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --domain` | Target domain **(required)** | — |
| `-w, --wordlist` | Path to custom wordlist | Built-in (2,100+) |
| `-o, --output` | Output base name (`.json` + `.csv`) | None |
| `-v, --verbose` | Debug-level logging | Off |
| `-q, --quiet` | Suppress all non-result output | Off |

### Discovery Control

| Flag | Description | Default |
|------|-------------|---------|
| `--no-crtsh` | Skip Certificate Transparency lookup | Off |
| `--no-permutations` | Skip permutation engine | Off |
| `--max-permutations` | Cap permutation candidates | 5,000 |
| `--recursive` | Recurse into discovered subdomains | Off |
| `--depth` | Maximum recursion depth | 2 |
| `--live-check` | HTTP status code checks | Off |

### Performance Tuning

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --concurrency` | Max concurrent DNS tasks | 100 |
| `--rate-limit` | Queries per second | 500 |
| `--timeout` | DNS timeout (seconds) | 5.0 |
| `--retries` | Retry count on timeout | 3 |
| `--nameservers` | Custom DNS servers (comma-separated) | Google + Cloudflare |

### Output Formats

| Flag | Description |
|------|-------------|
| `--json-only` | Export JSON only (skip CSV) |
| `--csv-only` | Export CSV only (skip JSON) |
| `--no-table` | Suppress terminal table |

## 💡 Examples

<details>
<summary><b>Basic enumeration</b></summary>

```bash
subrecon -d tesla.com
```

```
  ____        _     ____
 / ___| _   _| |__ |  _ \ ___  ___ ___  _ __
 \___ \| | | | '_ \| |_) / _ \/ __/ _ \| '_ \
  ___) | |_| | |_) |  _ <  __/ (_| (_) | | | |
 |____/ \__,_|_.__/|_| \_\___|\___\___/|_| |_|
                                        v1.0.0

[*] Target domain: tesla.com
[*] Phase 1: Wildcard detection
[*] No wildcard DNS detected
[*] Phase 2: Passive discovery
[*] crt.sh returned 142 unique subdomains
...
--------------------------------------------------------------
SUBDOMAIN              | IP ADDRESS(ES)    | SOURCE
--------------------------------------------------------------
api.tesla.com          | 199.66.9.47       | crt.sh, brute-force
mail.tesla.com         | 13.111.14.1       | dns-records
shop.tesla.com         | 23.55.161.139     | brute-force
...
--------------------------------------------------------------
  Total: 287 unique subdomains
```

</details>

<details>
<summary><b>Full recon with export</b></summary>

```bash
subrecon -d example.com \
  --live-check \
  --recursive --depth 2 \
  -c 200 \
  -o example_scan \
  -v
```

Produces:
- `example_scan.json` — structured JSON with metadata
- `example_scan.csv` — spreadsheet-ready CSV
- Terminal table with HTTP status codes

</details>

<details>
<summary><b>Custom wordlist + quiet mode</b></summary>

```bash
subrecon -d target.com -w wordlists/large.txt -q --json-only -o results
```

</details>

## 🏗️ Architecture

```
subrecon/
├── subrecon/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # Entry point (python -m subrecon)
│   ├── cli.py               # Argument parser
│   ├── engine.py            # Main orchestrator
│   ├── constants.py         # Wordlist, permutation words, banner
│   ├── models.py            # Data classes
│   ├── core/
│   │   ├── __init__.py
│   │   ├── resolver.py      # Async DNS resolver with retries
│   │   ├── wildcard.py      # Wildcard detection
│   │   ├── passive.py       # crt.sh + DNS record parsing
│   │   ├── bruteforce.py    # DNS brute-force engine
│   │   ├── permutations.py  # Permutation generator
│   │   └── httpcheck.py     # HTTP live checker
│   ├── output/
│   │   ├── __init__.py
│   │   ├── table.py         # Terminal table formatter
│   │   ├── json_export.py   # JSON exporter
│   │   └── csv_export.py    # CSV exporter
│   └── utils/
│       ├── __init__.py
│       ├── ratelimit.py     # Token-bucket rate limiter
│       └── logging.py       # Logging setup
├── tests/
│   ├── __init__.py
│   ├── test_resolver.py
│   ├── test_wildcard.py
│   ├── test_passive.py
│   ├── test_permutations.py
│   └── test_output.py
├── wordlists/
│   └── common.txt           # Default wordlist (exported)
├── .github/
│   ├── workflows/
│   │   └── ci.yml           # GitHub Actions CI
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
├── .gitignore
├── LICENSE
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── Makefile
├── setup.py
├── setup.cfg
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

### Enumeration Pipeline

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Wildcard    │────▶│   Passive    │────▶│  Brute-Force │
│  Detection   │     │  (crt.sh +   │     │  (Async DNS) │
│              │     │   DNS parse) │     │              │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                │
                    ┌──────────────┐     ┌───────▼───────┐
                    │  HTTP Live   │◀────│  Permutation  │
                    │  Check       │     │  Engine       │
                    └──────┬───────┘     └───────────────┘
                           │          ▲
                           ▼          │ (if --recursive)
                    ┌──────────────┐   │
                    │   Output     │   │
                    │ Table/JSON/  │───┘
                    │    CSV       │
                    └──────────────┘
```

## 🧪 Testing

```bash
# Run all tests
make test

# With coverage
make coverage

# Lint
make lint
```

## 📄 Output Formats

### JSON Structure

```json
{
  "meta": {
    "tool": "SubRecon",
    "version": "1.0.0",
    "timestamp": "2026-03-30T14:00:00Z",
    "domain": "example.com",
    "total": 287
  },
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "ips": "93.184.216.34",
      "cname_chain": "api.example.com.cdn.cloudflare.net",
      "source": "crt.sh, brute-force",
      "http_status": 200,
      "http_redirect": null
    }
  ]
}
```

### CSV Columns

```
subdomain, ips, cname_chain, source, http_status, http_redirect
```

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing and research only**. Always ensure you have explicit permission before enumerating subdomains of any domain you do not own. Unauthorized reconnaissance may violate applicable laws and terms of service.

The authors assume no liability for misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📝 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with ❤️ for the security community**

⭐ Star this repo if you find it useful!

</div>
