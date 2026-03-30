#!/usr/bin/env python3
"""
SubEnum - Comprehensive Subdomain Enumeration Tool

Combines passive discovery, active brute-forcing, permutation generation,
and live HTTP checks into a single, fast, async-powered CLI tool.

No API keys required. Uses only publicly available data sources.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import os
import random
import re
import string
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Attempt to import optional heavy dependencies; guide the user if missing.
# ---------------------------------------------------------------------------
_MISSING: list[str] = []

try:
    import aiodns
except ImportError:
    _MISSING.append("aiodns")

try:
    import aiohttp
except ImportError:
    _MISSING.append("aiohttp")

try:
    from tqdm import tqdm
    from tqdm.asyncio import tqdm as atqdm
except ImportError:
    _MISSING.append("tqdm")
    tqdm = None  # type: ignore
    atqdm = None  # type: ignore

if _MISSING:
    print(
        f"[!] Missing required packages: {', '.join(_MISSING)}\n"
        f"    Install with:  pip install {' '.join(_MISSING)}",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION = "1.0.0"
BANNER = rf"""
  ____        _     _____
 / ___| _   _| |__ | ____|_ __  _   _ _ __ ___
 \___ \| | | | '_ \|  _| | '_ \| | | | '_ ` _ \
  ___) | |_| | |_) | |___| | | | |_| | | | | | |
 |____/ \__,_|_.__/|_____|_| |_|\__,_|_| |_| |_|
                              v{VERSION}
  Comprehensive Subdomain Enumeration Tool
"""

DEFAULT_CONCURRENCY = 100
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 5.0
DEFAULT_RATE_LIMIT = 500          # max DNS queries / second
WILDCARD_CHECK_COUNT = 12         # random labels to test wildcard
HTTP_TIMEOUT = 8

# Resolvers to cycle through (public DNS)
PUBLIC_RESOLVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "64.6.64.6",
    "64.6.65.6",
]

# ---------------------------------------------------------------------------
# Built-in wordlist  (1 050 entries – common subdomain prefixes)
# ---------------------------------------------------------------------------
BUILTIN_WORDLIST: list[str] = sorted(set("""
a aa aaa ab abc abs ac academy access account accounts acl acm ad adam
adfs admin admin1 admin2 admin3 administration administrator admins ads adserver
adv advisory af ag agent ai air ajax ak al ala alert alerts alpha am
amazon analytics android ann announcements ant antivirus ap apache api api1
api2 api3 api-docs api-gateway api-v2 apis app app1 app2 app3 apple application
applications apps appstore ar arch archive archives area aria art as ascii
asset assets at atlas att au auth auth0 authenticate auto autoconfig
autodiscover av aw aws ax az azure b ba back backend backup backups ban
banner bar base bastion bb bc bd be beta bg bi billing bind bit biz bk bl
blackboard blog blog1 blog2 blogs bm bn board bob bond book books boot
bot box br bridge broadcast broker bs bt bug bugtracker bugs build builder
builds bulk bus business buy bw bx by bz c ca cache cal calendar cam
camera camp campaign can canal cap car card care career careers cart cas
catalog cdn cdn1 cdn2 central cert certs cf cg ch challenge change channel
channels chat check checkout chi ci cid cifs cisco citrix city ck cl
class classic click client clients clone cloud cloud1 cloud2 cloudflare
cluster clusters cm cms cn co code col collaboration collect com comm
commerce common community comp compliance compute con conf conference
config configuration connect console consumer contact contacts content
control controller converter cookie core corp corporate council count counter
course courses cp cpanel cr crl crm crowd crypto cs css ct cu custom customer
customers cv cvs cw cx cy cz d da dad dam dashboard data database db db1
db2 db3 dc dd de deal deals debug default del demo demo1 demo2 deploy
design desktop dev dev1 dev2 dev3 devel develop developer developers devops
df dg dh di dir direct directory disable disco discover discovery
discuss discussion disk dl dm dmz dns dns0 dns1 dns2 dns3 do doc docker
docs document documents domain domains donate download downloads dp dq
dr drive drop drupal ds dt du dx dy dz e ea east ec echo ed edge edit
editor edu education el elastic elasticsearch election element elite em
email embed emp employee employees en endpoint eng engine engineering
enter enterprise env ep eq er erp es et eu ev event events ex exchange
exec explore export express ext extern external extra extranet ey ez f
fa fac facebook faq farm fast fax fb fc fd fe feed feeds fi fie file files
film fin finance financial find fire firewall fix fl flag flash flow fm fn
fo food for force forest forge form forms forum forums forward found fox fp
fq fr framework free fresh front frontend fs ft ftp ftp1 ftp2 fu fun fund fw
fx fy fz g ga gal gallery game games gateway gc gd ge get gf gg gh gi git
github gl global gm gn go gold good google gov gp gq gr graph graphite graphql
green group groups grow gs gt gu guard guest guide gw gx gy gz h ha hack
hadoop harbor hb hc hd he health help helpdesk hg hh hi his history hk hl
hm hn ho home homebase hook hooks host hosting hostname hot hotel hp hq hr hs
ht html http hub hx hy hz i ia iam ib ic id identity idp ig ih ii ij ik il
im image images imap img imp import in inbox include index india info infra
infrastructure ing inner inset inside install instance int integration
intel internal internet intra intranet intro invest io ip iq ir irc is iso
it its iv ix iy iz j ja jab jack jam java jb jc jd je jen jenkins jf jg jh
ji jira jk jl jm jn jo job jobs john join journal jp jq jr js json jt ju
jump jv jw jx jy jz k ka kb kc kd ke key keys kg kh ki kl km kn ko kp kq
kr ks kt ku kv kw kx ky kz l la lab labs lan landing launch lb lc ld le
legacy len lib library license light link linkedin linux list lists live
lk ll lm ln lo load local localhost log login logout logs lp lq lr ls lt lu
lv lw lx ly lz m m1 m2 m3 ma mac machine mail mail1 mail2 mail3 mailbox
mailgun mailhost main manage management manager map maps mar mark market
marketing master mb mc md me media meet member members memo menu mesh
message messages meta metrics mf mg mh mi mic micro middleware min mirror
mix mk ml mm mn mo mob mobile mock module mon money monitor monitoring moon
mq mr ms msg mt mu music mv mw mx my mysql mz n na name nameserver nas nat
nav nb nc nd ne net netbox netscaler network new news next nf ng nh ni nk nl
nm nn no noc node north note notes notify now np nq nr ns ns0 ns1 ns2 ns3 ns4
nt nu nv nw nx ny nz o oa ob oc od oe of offer office og oh oi oj ok ol
old om on one online oo op open openid ops opt or oracle order org origin os
ot oud out outlook ov ow ox oy oz p pa pack page pager pages paid pan
panel park partner partners pass password paste pay payment pb pc pd pe pen
people per pet pg ph phone photo photos pi ping pip pk pl plan platform play
player plaza plm pm pn po poc pod point poll pool pop portal pos post
postgres power pp pq pr pre premium press preview private pro prod
product production profile program project projects promo proxy ps pt
pub public pull puppet push pv pw px py pz q qa qr qs qt qu query queue
quick quota qw qx qy qz r ra rabbit rac rack radar radio raft ran ranch
random range ras raw rb rc rd re read real rec record red redirect ref
reg register registry relay release remote render rep repo report reports
request res research reset resource resources rest review rh ri ring risk
rm rn ro robot root ros route router rp rq rr rs rss rt ru run rv rw rx
ry rz s s1 s2 s3 sa safe sales sample san sandbox sap sat save sb sc
scan schedule schema sd se search sec secret secure security seed self send
seo ser server service services session set sf sg sh share shared shell ship
shop si sign signal sim simple site sites sk sl slack slave sm smtp sn snap
so soc social socket soft software sol son south sp space spark spec speed
splunk sport spring sql sr ss ssh ssl sso st staff stage staging star start
stat static stats status step stock stop store stream strong student su
sub submit sun sup super support survey sv sw switch sx sy sync sys syslog
system sz t ta tab table tag tap target task tb tc td te team teams tech
tel temp template ten term terminal test test1 test2 test3 testing text tf
tg th ticket time tip tk tl tm tn to token tool tools top tor track tracker
traffic trail train transfer travel tree trial ts tt tu tunnel tv tw tx
ty tz u ua ub uc ud ue uf ug uh ui uk ul um un union unit unix up update
upload uq ur us user users ut uu uv uw ux uy uz v v1 v2 v3 va vault vb vc
vd ve vendor verify video view vim vip virtual vision vm vn vo voice void vp
vpn vps vq vr vs vt vu vw vx vy vz w wa wall wan war watch way wb wc wd we
web web1 web2 web3 webadmin webapi webapp webdisk weblog webmail webmaster
webproxy webserver west wf wg wh what white whm whois who wi wiki win
windows wire wl wm wn wo word wordpress work worker works world wp wq wr ws
wt wu wv ww www www0 www1 www2 www3 wx wy wz x x1 xa xb xc xd xe xf xg xh
xi xj xk xl xm xml xn xo xp xq xr xs xt xu xv xw xx xy xz y ya yb yc yd
ye yf yg yh yi yj yk yl ym yn yo yp yq yr ys yt yu yv yw yx yy yz z za zb
zc zd ze zen zero zf zg zh zi zj zk zl zm zn zo zone zoo zp zq zr zs zt zu
zv zw zx zy zz
""".split()))

# Permutation helper words
PERM_WORDS = [
    "dev", "staging", "prod", "test", "stage", "uat", "qa", "demo",
    "beta", "alpha", "old", "new", "internal", "external", "backup",
    "tmp", "temp", "v2", "v3", "api", "app", "web", "mail", "admin",
    "portal", "secure", "public", "private", "mgmt", "monitor", "sandbox",
]

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
logger = logging.getLogger("subenum")


def setup_logging(verbose: bool, quiet: bool):
    level = logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.setLevel(level)
    logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class SubdomainResult:
    subdomain: str
    ips: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    http_status: Optional[int] = None
    http_redirect: Optional[str] = None

    def merge(self, other: "SubdomainResult"):
        self.ips = sorted(set(self.ips + other.ips))
        self.cname_chain = other.cname_chain or self.cname_chain
        self.sources = sorted(set(self.sources + other.sources))
        if other.http_status is not None:
            self.http_status = other.http_status
            self.http_redirect = other.http_redirect


# ---------------------------------------------------------------------------
# Rate limiter (token-bucket)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, rate: float):
        self._rate = rate
        self._tokens = rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


# ---------------------------------------------------------------------------
# DNS resolver wrapper with retry + rate-limit
# ---------------------------------------------------------------------------
class AsyncResolver:
    def __init__(
        self,
        concurrency: int = DEFAULT_CONCURRENCY,
        retries: int = DEFAULT_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        nameservers: Optional[list[str]] = None,
    ):
        self.concurrency = concurrency
        self.retries = retries
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)
        self.rate_limiter = RateLimiter(rate_limit)
        self.nameservers = nameservers or PUBLIC_RESOLVERS[:]
        self._resolver: Optional[aiodns.DNSResolver] = None

    def _get_resolver(self) -> aiodns.DNSResolver:
        if self._resolver is None:
            self._resolver = aiodns.DNSResolver(
                nameservers=self.nameservers,
                timeout=self.timeout,
                tries=1,
                rotate=True,
            )
        return self._resolver

    async def resolve(self, name: str, rdtype: str = "A") -> list:
        """Resolve *name* with retries and rate limiting."""
        resolver = self._get_resolver()
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            async with self.sem:
                await self.rate_limiter.acquire()
                try:
                    result = await resolver.query(name, rdtype)
                    return result
                except aiodns.error.DNSError as exc:
                    last_exc = exc
                    code = exc.args[0] if exc.args else -1
                    # NXDOMAIN / NODATA → stop retrying
                    if code in (1, 4):  # ARES_ENOTFOUND, ARES_ENODATA
                        raise
                    # Timeout / server failure → retry with backoff
                    wait = 0.3 * attempt + random.uniform(0, 0.2)
                    logger.debug("DNS retry %d/%d for %s (%s): %s", attempt, self.retries, name, rdtype, exc)
                    await asyncio.sleep(wait)
                except Exception as exc:
                    last_exc = exc
                    break
        raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------
async def detect_wildcard(resolver: AsyncResolver, domain: str) -> set[str]:
    """Return the set of IPs that a wildcard *.domain resolves to, or empty."""
    random_labels = [
        "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(12, 18)))
        for _ in range(WILDCARD_CHECK_COUNT)
    ]
    wildcard_ips: dict[str, int] = defaultdict(int)
    for label in random_labels:
        fqdn = f"{label}.{domain}"
        try:
            answers = await resolver.resolve(fqdn, "A")
            for a in answers:
                wildcard_ips[a.host] += 1
        except Exception:
            pass

    # If ≥ 75 % of random probes return the same IP, it's a wildcard
    threshold = int(WILDCARD_CHECK_COUNT * 0.75)
    result = {ip for ip, cnt in wildcard_ips.items() if cnt >= threshold}
    if result:
        logger.warning("Wildcard detected for *.%s → %s", domain, ", ".join(result))
    return result


# ---------------------------------------------------------------------------
# Passive: crt.sh (Certificate Transparency)
# ---------------------------------------------------------------------------
async def query_crtsh(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """Pull subdomains from crt.sh CT log aggregator."""
    subs: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                logger.warning("crt.sh returned HTTP %d", resp.status)
                return subs
            data = await resp.json(content_type=None)
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)
        logger.info("crt.sh returned %d unique names", len(subs))
    except Exception as exc:
        logger.warning("crt.sh query failed: %s", exc)
    return subs


# ---------------------------------------------------------------------------
# Passive: DNS record mining (MX, NS, SOA, TXT, CNAME)
# ---------------------------------------------------------------------------
async def mine_dns_records(resolver: AsyncResolver, domain: str) -> set[str]:
    """Extract subdomain hints from various DNS record types."""
    found: set[str] = set()

    async def _try(rdtype: str):
        try:
            results = await resolver.resolve(domain, rdtype)
            return results
        except Exception:
            return []

    # MX records
    for r in await _try("MX"):
        host = r.host.rstrip(".").lower()
        if host.endswith(f".{domain}"):
            found.add(host)

    # NS records
    for r in await _try("NS"):
        host = r.host.rstrip(".").lower()
        if host.endswith(f".{domain}"):
            found.add(host)

    # SOA
    for r in await _try("SOA"):
        for attr in ("mname", "rname"):
            val = getattr(r, attr, "").rstrip(".").lower()
            if val.endswith(f".{domain}"):
                found.add(val)

    # TXT – look for domains mentioned inside SPF / DKIM / DMARC etc.
    for r in await _try("TXT"):
        text = r.text if isinstance(r.text, str) else r.text.decode(errors="ignore")
        pattern = re.compile(r"([a-zA-Z0-9_.-]+\." + re.escape(domain) + r")\b")
        for m in pattern.finditer(text):
            found.add(m.group(1).lower())

    logger.info("DNS record mining found %d names", len(found))
    return found


# ---------------------------------------------------------------------------
# Active: Brute-force resolution
# ---------------------------------------------------------------------------
async def brute_resolve(
    resolver: AsyncResolver,
    domain: str,
    wordlist: list[str],
    wildcard_ips: set[str],
    source_tag: str = "brute",
    progress: bool = True,
    quiet: bool = False,
) -> dict[str, SubdomainResult]:
    """Resolve wordlist entries against *domain*, filtering wildcards."""
    results: dict[str, SubdomainResult] = {}
    tasks: list[tuple[str, asyncio.Task]] = []

    async def _probe(fqdn: str) -> Optional[SubdomainResult]:
        try:
            answers = await resolver.resolve(fqdn, "A")
        except Exception:
            return None
        ips = [a.host for a in answers]
        # Filter wildcard hits
        if wildcard_ips and set(ips).issubset(wildcard_ips):
            return None
        # Check for CNAME chain
        cnames: list[str] = []
        try:
            cname_ans = await resolver.resolve(fqdn, "CNAME")
            cnames = [c.cname.rstrip(".") for c in cname_ans]
        except Exception:
            pass
        return SubdomainResult(subdomain=fqdn, ips=ips, cname_chain=cnames, sources=[source_tag])

    fqdns = [f"{w}.{domain}" for w in wordlist]
    coros = [_probe(f) for f in fqdns]

    iterator: list[Optional[SubdomainResult]]
    if progress and not quiet and atqdm is not None:
        gathered = []
        for coro in atqdm(asyncio.as_completed(coros), total=len(coros), desc=f"  Bruting {domain}", unit="q", leave=False):
            gathered.append(await coro)
        iterator = gathered
    else:
        iterator = await asyncio.gather(*coros)

    for res in iterator:
        if res is not None:
            key = res.subdomain.lower()
            if key in results:
                results[key].merge(res)
            else:
                results[key] = res

    return results


# ---------------------------------------------------------------------------
# Permutation engine
# ---------------------------------------------------------------------------
def generate_permutations(discovered: set[str], domain: str) -> set[str]:
    """Generate candidate subdomains by mutating discovered names."""
    candidates: set[str] = set()
    for fqdn in discovered:
        prefix = fqdn[: -(len(domain) + 1)]  # strip .domain
        if not prefix:
            continue
        parts = prefix.split(".")

        for word in PERM_WORDS:
            # prepend / append word with dash
            candidates.add(f"{word}-{prefix}.{domain}")
            candidates.add(f"{prefix}-{word}.{domain}")
            # prepend / append as new label
            candidates.add(f"{word}.{prefix}.{domain}")
            candidates.add(f"{prefix}.{word}.{domain}")

        # Insert numbers 0-9
        for n in range(10):
            candidates.add(f"{prefix}{n}.{domain}")
            candidates.add(f"{prefix}-{n}.{domain}")
            candidates.add(f"{n}{prefix}.{domain}")
            candidates.add(f"{n}-{prefix}.{domain}")

        # Swap dashes ↔ dots in first label
        if "-" in parts[0]:
            swapped = parts[0].replace("-", ".")
            candidates.add(f"{swapped}.{'.'.join(parts[1:]) + '.' if len(parts) > 1 else ''}{domain}")
        if len(parts) > 1:
            merged = parts[0] + "-" + parts[1]
            rest = ".".join(parts[2:])
            candidates.add(f"{merged}.{rest + '.' if rest else ''}{domain}")

    # Remove any that don't end with the domain or equal the domain
    candidates = {c for c in candidates if c.endswith(f".{domain}") and c != f".{domain}" and c != domain}
    # Deduplicate against already discovered
    candidates -= discovered
    logger.info("Permutation engine generated %d candidates", len(candidates))
    return candidates


# ---------------------------------------------------------------------------
# HTTP live check
# ---------------------------------------------------------------------------
async def http_check(
    subdomains: dict[str, SubdomainResult],
    concurrency: int = 50,
    progress: bool = True,
    quiet: bool = False,
):
    """Optional: hit each subdomain over HTTP/HTTPS to get status code."""
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)

    async def _check(res: SubdomainResult):
        for scheme in ("https", "http"):
            url = f"{scheme}://{res.subdomain}"
            try:
                async with sem:
                    async with aiohttp.ClientSession(connector_owner=False, connector=connector) as sess:
                        async with sess.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                            allow_redirects=False,
                        ) as resp:
                            res.http_status = resp.status
                            res.http_redirect = resp.headers.get("Location")
                            return
            except Exception:
                continue

    coros = [_check(r) for r in subdomains.values()]
    if progress and not quiet and atqdm is not None:
        for coro in atqdm(asyncio.as_completed(coros), total=len(coros), desc="  HTTP probe", unit="req", leave=False):
            await coro
    else:
        await asyncio.gather(*coros, return_exceptions=True)

    await connector.close()


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def print_table(results: dict[str, SubdomainResult], show_http: bool = False):
    """Pretty-print results to terminal."""
    if not results:
        print("\n  No subdomains discovered.\n")
        return

    sorted_keys = sorted(results.keys())
    # Column widths
    w_sub = max(len(r.subdomain) for r in results.values())
    w_ip = max((len(", ".join(r.ips)) for r in results.values()), default=4)
    w_cn = max((len(" → ".join(r.cname_chain)) if r.cname_chain else 1 for r in results.values()), default=5)
    w_src = max((len(", ".join(r.sources)) for r in results.values()), default=6)

    w_sub = max(w_sub, 9)
    w_ip = min(max(w_ip, 11), 40)
    w_cn = min(max(w_cn, 5), 50)
    w_src = max(w_src, 7)

    header = f"  {'Subdomain':<{w_sub}}  {'IP(s)':<{w_ip}}  {'CNAME':<{w_cn}}  {'Source':<{w_src}}"
    if show_http:
        header += "  HTTP"
    sep = "  " + "─" * (w_sub + w_ip + w_cn + w_src + 8 + (6 if show_http else 0))
    print(f"\n{sep}\n{header}\n{sep}")

    for key in sorted_keys:
        r = results[key]
        ip_str = ", ".join(r.ips)[:40]
        cn_str = (" → ".join(r.cname_chain) if r.cname_chain else "")[:50]
        src_str = ", ".join(r.sources)
        line = f"  {r.subdomain:<{w_sub}}  {ip_str:<{w_ip}}  {cn_str:<{w_cn}}  {src_str:<{w_src}}"
        if show_http:
            st = str(r.http_status) if r.http_status else "-"
            line += f"  {st:>4}"
        print(line)

    print(f"{sep}\n  Total: {len(results)} unique subdomains\n")


def export_json(results: dict[str, SubdomainResult], path: str):
    data = [asdict(r) for r in sorted(results.values(), key=lambda x: x.subdomain)]
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    logger.info("JSON written → %s", path)


def export_csv(results: dict[str, SubdomainResult], path: str):
    fieldnames = ["subdomain", "ips", "cname_chain", "sources", "http_status", "http_redirect"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in sorted(results.values(), key=lambda x: x.subdomain):
            writer.writerow({
                "subdomain": r.subdomain,
                "ips": "|".join(r.ips),
                "cname_chain": "|".join(r.cname_chain),
                "sources": "|".join(r.sources),
                "http_status": r.http_status or "",
                "http_redirect": r.http_redirect or "",
            })
    logger.info("CSV written → %s", path)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
async def run(args: argparse.Namespace):
    domain = args.domain.lower().strip().rstrip(".")
    all_results: dict[str, SubdomainResult] = {}

    def _merge(new: dict[str, SubdomainResult]):
        for key, res in new.items():
            key = key.lower()
            if key in all_results:
                all_results[key].merge(res)
            else:
                all_results[key] = res

    resolver = AsyncResolver(
        concurrency=args.concurrency,
        retries=args.retries,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        nameservers=args.resolvers.split(",") if args.resolvers else None,
    )

    # Load custom wordlist or use built-in
    if args.wordlist:
        with open(args.wordlist) as fh:
            wordlist = sorted(set(line.strip().lower() for line in fh if line.strip()))
        logger.info("Loaded %d words from %s", len(wordlist), args.wordlist)
    else:
        wordlist = BUILTIN_WORDLIST[:]
        logger.info("Using built-in wordlist (%d words)", len(wordlist))

    show_progress = not args.quiet

    # ── Phase 1: Passive ────────────────────────────────────────────────
    if not args.no_passive:
        if show_progress:
            print("\n[*] Phase 1 — Passive discovery")

        # crt.sh
        if show_progress:
            print("  → Querying crt.sh …")
        async with aiohttp.ClientSession() as session:
            crtsh_subs = await query_crtsh(domain, session)
        for s in crtsh_subs:
            key = s.lower()
            if key not in all_results:
                all_results[key] = SubdomainResult(subdomain=s, sources=["crt.sh"])
            else:
                all_results[key].sources = sorted(set(all_results[key].sources + ["crt.sh"]))
        if show_progress:
            print(f"    crt.sh: {len(crtsh_subs)} subdomains")

        # DNS record mining
        if show_progress:
            print("  → Mining DNS records (MX, NS, SOA, TXT) …")
        dns_subs = await mine_dns_records(resolver, domain)
        for s in dns_subs:
            key = s.lower()
            if key not in all_results:
                all_results[key] = SubdomainResult(subdomain=s, sources=["dns-records"])
            else:
                all_results[key].sources = sorted(set(all_results[key].sources + ["dns-records"]))
        if show_progress:
            print(f"    DNS records: {len(dns_subs)} subdomains")

    # ── Phase 2: Wildcard detection ─────────────────────────────────────
    if show_progress:
        print("\n[*] Phase 2 — Wildcard detection")
    wildcard_ips = await detect_wildcard(resolver, domain)
    if wildcard_ips and show_progress:
        print(f"    ⚠ Wildcard IPs: {', '.join(wildcard_ips)}")
    elif show_progress:
        print("    ✓ No wildcard detected")

    # ── Phase 3: Active brute-force ─────────────────────────────────────
    if not args.no_brute:
        if show_progress:
            print(f"\n[*] Phase 3 — Brute-force ({len(wordlist)} words, concurrency={args.concurrency})")
        brute_results = await brute_resolve(
            resolver, domain, wordlist, wildcard_ips,
            source_tag="brute", progress=show_progress, quiet=args.quiet,
        )
        _merge(brute_results)
        if show_progress:
            print(f"    Brute-force discovered: {len(brute_results)} subdomains")

    # ── Phase 3b: Recursive enumeration ─────────────────────────────────
    if args.recursive and not args.no_brute:
        depth = 0
        max_depth = args.recursive_depth
        bases = {r.subdomain for r in all_results.values() if r.subdomain != domain}
        seen_bases: set[str] = set()

        while depth < max_depth and bases - seen_bases:
            depth += 1
            new_bases = bases - seen_bases
            if show_progress:
                print(f"\n[*] Phase 3 — Recursive depth {depth}/{max_depth} ({len(new_bases)} base domains)")
            for base in sorted(new_bases):
                seen_bases.add(base)
                sub_wc = await detect_wildcard(resolver, base)
                rr = await brute_resolve(
                    resolver, base, wordlist[:200], sub_wc | wildcard_ips,
                    source_tag=f"recursive-d{depth}", progress=show_progress, quiet=args.quiet,
                )
                _merge(rr)
            bases = {r.subdomain for r in all_results.values() if r.subdomain != domain} - seen_bases

    # ── Phase 4: Permutation engine ─────────────────────────────────────
    if not args.no_permutation:
        discovered_set = set(all_results.keys())
        perm_candidates = generate_permutations(discovered_set, domain)
        if perm_candidates:
            if show_progress:
                print(f"\n[*] Phase 4 — Permutation engine ({len(perm_candidates)} candidates)")
            # Extract labels from full FQDNs for brute_resolve interface
            perm_labels = [c[: -(len(domain) + 1)] for c in perm_candidates]
            perm_results = await brute_resolve(
                resolver, domain, perm_labels, wildcard_ips,
                source_tag="permutation", progress=show_progress, quiet=args.quiet,
            )
            _merge(perm_results)
            if show_progress:
                print(f"    Permutations discovered: {len(perm_results)} subdomains")

    # ── Phase 5: Resolve IPs for passive-only entries ───────────────────
    if show_progress:
        print("\n[*] Phase 5 — Resolving passive-only entries")
    to_resolve = [r for r in all_results.values() if not r.ips]
    resolved_count = 0
    for r in to_resolve:
        try:
            answers = await resolver.resolve(r.subdomain, "A")
            r.ips = [a.host for a in answers]
            # Filter wildcards
            if wildcard_ips and set(r.ips).issubset(wildcard_ips):
                r.ips = []
                del all_results[r.subdomain.lower()]
                continue
            resolved_count += 1
        except Exception:
            pass
        # Also check CNAME
        if not r.cname_chain:
            try:
                cname_ans = await resolver.resolve(r.subdomain, "CNAME")
                r.cname_chain = [c.cname.rstrip(".") for c in cname_ans]
            except Exception:
                pass
    if show_progress:
        print(f"    Resolved {resolved_count}/{len(to_resolve)} entries")

    # ── Phase 6: Optional HTTP live-check ───────────────────────────────
    if args.http_check:
        live_targets = {k: v for k, v in all_results.items() if v.ips}
        if live_targets:
            if show_progress:
                print(f"\n[*] Phase 6 — HTTP live check ({len(live_targets)} hosts)")
            await http_check(live_targets, concurrency=min(args.concurrency, 50), progress=show_progress, quiet=args.quiet)

    # ── Output ──────────────────────────────────────────────────────────
    if not args.quiet:
        print_table(all_results, show_http=args.http_check)

    if args.output_json:
        export_json(all_results, args.output_json)
        if not args.quiet:
            print(f"  ✓ JSON → {args.output_json}")
    if args.output_csv:
        export_csv(all_results, args.output_csv)
        if not args.quiet:
            print(f"  ✓ CSV  → {args.output_csv}")

    return all_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subenum",
        description="SubEnum — Comprehensive Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python subenum.py example.com
  python subenum.py example.com --http-check -oJ results.json
  python subenum.py example.com -w custom.txt -c 200 --recursive
  python subenum.py example.com --no-brute --no-permutation   # passive only
        """,
    )
    p.add_argument("domain", help="Target domain to enumerate")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    # Passive
    g_pass = p.add_argument_group("passive options")
    g_pass.add_argument("--no-passive", action="store_true", help="Skip passive discovery (crt.sh, DNS mining)")

    # Brute-force
    g_brute = p.add_argument_group("brute-force options")
    g_brute.add_argument("--no-brute", action="store_true", help="Skip DNS brute-force")
    g_brute.add_argument("-w", "--wordlist", metavar="FILE", help="Custom wordlist (one word per line)")
    g_brute.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help=f"Concurrent tasks (default: {DEFAULT_CONCURRENCY})")
    g_brute.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help=f"DNS retries (default: {DEFAULT_RETRIES})")
    g_brute.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"DNS timeout in seconds (default: {DEFAULT_TIMEOUT})")
    g_brute.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT, help=f"Max DNS queries/sec (default: {DEFAULT_RATE_LIMIT})")
    g_brute.add_argument("--resolvers", metavar="IPs", help="Comma-separated nameserver IPs")

    # Recursive
    g_rec = p.add_argument_group("recursive options")
    g_rec.add_argument("-r", "--recursive", action="store_true", help="Recursively enumerate discovered subdomains")
    g_rec.add_argument("--recursive-depth", type=int, default=2, metavar="N", help="Max recursion depth (default: 2)")

    # Permutation
    g_perm = p.add_argument_group("permutation options")
    g_perm.add_argument("--no-permutation", action="store_true", help="Skip permutation engine")

    # HTTP
    g_http = p.add_argument_group("HTTP options")
    g_http.add_argument("--http-check", action="store_true", help="Probe discovered hosts for HTTP status codes")

    # Output
    g_out = p.add_argument_group("output options")
    g_out.add_argument("-oJ", "--output-json", metavar="FILE", help="Export results to JSON")
    g_out.add_argument("-oC", "--output-csv", metavar="FILE", help="Export results to CSV")
    g_out.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    g_out.add_argument("-q", "--quiet", action="store_true", help="Suppress all output except final results")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose, args.quiet)

    if not args.quiet:
        print(BANNER)

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted — partial results not saved.")
        sys.exit(130)


if __name__ == "__main__":
    main()
