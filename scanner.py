#!/usr/bin/env python3
"""
Safe Org Recon GUI — v4.1 (Unified + Progress Bar)
Passive, compliance-friendly organizational recon with expanded intel, autosave, and exports.

What it does (PASSIVE by default):
  • security.txt, robots.txt (+ sitemap discovery)
  • Root HTTP headers (HEAD + GET), redirects, title, cookie flags
  • Security-header check (HSTS, CSP, etc.) + quick CSP linter
  • TLS certificate metadata (issuer/subject/validity)
  • DNS (A/AAAA/MX/TXT/NS/SOA) + SPF/DMARC summary
  • Subdomains from Certificate Transparency (crt.sh) + optional lite DNS bruteforce
  • Wildcard DNS detection
  • Suspicious subdomain scoring
  • Optional WHOIS (if `whois` exists)
  • Optional ASN/Org enrichment for resolved IPs via Team Cymru whois
  • Optional page titles for top-N subdomains
  • Exports Markdown + CSV/JSON; also writes a DOT graph of redirect chain when present
  • Autosaves all artifacts to ~/recon_reports
  • NEW: Determinate progress bar for subdomain processing (spins during setup)

Use only on assets you are explicitly authorized to assess.

Dependencies:
  pip install PyQt6 requests

Run:
  python3 safe_org_recon_gui_v4.py
"""
from __future__ import annotations
import sys, os, re, json, csv, ssl, socket, subprocess, shutil, datetime, random, time
from typing import List, Dict, Any, Tuple, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

# ---------------- Third-party
try:
    import requests
except Exception:
    print("This program requires the 'requests' package. Install with: pip install requests", file=sys.stderr)
    raise

# ---------------- Qt Imports
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout, QLabel, QLineEdit,
    QCheckBox, QSpinBox, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QFileDialog, QHBoxLayout, QHeaderView, QMessageBox, QProgressBar
)

requests.packages.urllib3.disable_warnings()

# ================= Utility Functions =================
def run(cmd: List[str], timeout: int = 20) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return out.strip()
    except Exception as e:
        return f"<error running {' '.join(cmd)}: {e}>"

def fetch_url(url: str, method: str = "GET", timeout: int = 12):
    try:
        if method == "HEAD":
            r = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        else:
            r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return r
    except Exception as e:
        return e

def tls_info(host: str, port: int = 443) -> Dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))
        not_before = cert.get('notBefore'); not_after  = cert.get('notAfter')
        def to_dt(s):
            return datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z") if s else None
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": str(to_dt(not_before)) if not_before else None,
            "not_after":  str(to_dt(not_after))  if not_after  else None,
        }
    except Exception as e:
        return {"error": str(e)}

def basic_dns(domain: str) -> Dict[str, str]:
    dig = shutil.which("dig")
    results: Dict[str, str] = {}
    if dig:
        for rr in ["A", "AAAA", "MX", "TXT", "NS", "SOA"]:
            out = run(["dig", "+short", rr, domain])
            results[rr] = out if out else "(none)"
        # SPF from TXT
        txt = results.get("TXT", "")
        spf = next((l for l in txt.splitlines() if "v=spf1" in l), "")
        # DMARC
        dmarc = run(["dig", "+short", "TXT", f"_dmarc.{domain}"]) or ""
        dmarc_line = next((l for l in dmarc.splitlines() if "v=DMARC1" in l), "")
        results["SPF"] = spf or "(none)"
        results["DMARC"] = dmarc_line or "(none)"
    else:
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = sorted({ai[4][0] for ai in infos})
            results["A/AAAA"] = "\n".join(ips) if ips else "(none)"
        except Exception as e:
            results["A/AAAA"] = f"<dns error: {e}>"
    return results

def is_private_ip(ip: str) -> bool:
    try:
        import ipaddress
        return getattr(ipaddress.ip_address(ip), 'is_private', False)
    except Exception:
        return False

def random_label(n: int = 10) -> str:
    import string as _s
    return ''.join(random.choice(_s.ascii_lowercase + _s.digits) for _ in range(n))

# ----- Root page parsing (no bs4 dependency)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
HREF_SRC_RE = re.compile(r"(?:href|src)\s*=\s*['\"]([^'^\"]+)['\"]", re.I)

TECH_HINTS = [
    ("WordPress", ["wp-content", "wp-includes", "wp-json"]),
    ("Shopify", ["cdn.shopify.com", "myshopify.com"]),
    ("Drupal", ["drupal.js", "drupal-settings-json"]),
    ("Next.js", ["_next/", "__NEXT_DATA__"]),
    ("React", ["static/js/main.", "react"]),
    ("Vue", ["vue.js", "vue.runtime."]),
    ("Angular", ["angular.min.js"]),
    ("Bootstrap", ["bootstrap.min.css", "bootstrap.min.js"]),
]

CDN_HEADER_HINTS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "server: cloudflare"]),
    ("Fastly", ["x-served-by", "via: 1.1 varnish"]),
    ("Akamai", ["akamai", "x-akamai"]),
    ("Amazon CloudFront", ["x-amz-cf-", "cloudfront"]),
]

SEC_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy",
]

# ================= Subdomain Enumeration =================
def ct_subdomains(domain: str, max_rows: int = 5000, pause: float = 1.0) -> Set[str]:
    subs: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20)
        if not isinstance(r, Exception) and r.status_code == 200:
            data = r.json()
            for row in data[:max_rows]:
                name_value = row.get("name_value", "")
                for line in name_value.splitlines():
                    line = line.strip().strip(".")
                    if line.endswith("." + domain) or line == domain:
                        subs.add(line.lower())
        time.sleep(pause)
    except Exception:
        pass
    return subs

def resolve_host(host: str) -> Dict[str, Any]:
    result = {"ips": [], "cname": "", "error": ""}
    dig = shutil.which("dig")
    if dig:
        out_a = run(["dig", "+short", "A", host])
        out_aaaa = run(["dig", "+short", "AAAA", host])
        ips: List[str] = []
        if not out_a.startswith("<error"): ips += [x for x in out_a.splitlines() if x]
        if not out_aaaa.startswith("<error"): ips += [x for x in out_aaaa.splitlines() if x]
        result["ips"] = list(sorted(set(ips)))
        out_cname = run(["dig", "+short", "CNAME", host])
        if not out_cname.startswith("<error"):
            result["cname"] = out_cname.splitlines()[0].strip(".") if out_cname else ""
        return result
    # Fallback: socket only
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({ai[4][0] for ai in infos})
        result["ips"] = ips
    except Exception as e:
        result["error"] = str(e)
    return result

def dns_bruteforce(domain: str, wordlist: Optional[str] = None, max_workers: int = 50, limit: int = 5000) -> Set[str]:
    candidates: Set[str] = set()
    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for i, w in enumerate(f):
                    if i >= limit: break
                    w = w.strip()
                    if not w or w.startswith("#"): continue
                    candidates.add(f"{w}.{domain}".lower())
        except Exception as e:
            print(f"[!] Could not read wordlist: {e}", file=sys.stderr)
    else:
        default_words = [
            "www","api","dev","test","staging","stage","qa","uat","preprod","beta","alpha",
            "old","backup","bak","temp","debug","admin","internal","intranet","vpn","ssh",
            "git","jenkins","grafana","kibana","prometheus","db","mysql","postgres","mongo",
            "redis","cache","smtp","mail","webmail","cpanel","ns1","ns2","sso","billing",
            "payments","cdn","static","assets","files","storage","s3","blob","upload","download"
        ]
        candidates = {f"{w}.{domain}".lower() for w in default_words}

    resolved: Set[str] = set()
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(resolve_host, host): host for host in candidates}
        for fut in as_completed(future_map):
            host = future_map[fut]
            try:
                res = fut.result()
                if res.get("ips") or res.get("cname"):
                    resolved.add(host)
            except Exception:
                pass
    return resolved

def detect_wildcard(domain: str) -> Tuple[bool, List[str]]:
    h1 = f"{random_label()}.{domain}"; h2 = f"{random_label()}.{domain}"
    r1 = resolve_host(h1); r2 = resolve_host(h2)
    ips1 = set(r1.get("ips", [])); ips2 = set(r2.get("ips", []))
    wildcard = bool(ips1 and ips2 and (ips1 & ips2))
    return wildcard, sorted(list(ips1 | ips2))

# ================= Suspicion Scoring =================
SUSPICIOUS_KEYWORDS = [
    "admin","adm","root","debug","dev","devel","developer","test","stage","staging",
    "qa","uat","preprod","beta","alpha","old","backup","bak","bkp","temp","tmp",
    "internal","intranet","private","vpn","ssh","rdp","citrix","owa","exchange",
    "git","jenkins","grafana","kibana","prometheus","graylog","splunk","elastic",
    "db","mysql","postgres","mssql","oracle","mongo","redis","kafka","rabbit",
    "billing","payments","invoice","sso","auth","oauth","login-old","legacy","v1","v2",
    "cdn","static","assets","files","storage","s3","blob","backup-restore"
]

CLOUD_CNAME_HINTS = [
    "s3.amazonaws.com","amazonaws.com","cloudfront.net","storage.googleapis.com",
    "github.io","azureedge.net","blob.core.windows.net","digitaloceanspaces.com",
    "fastly.net","netlify.app","herokuapp.com","pages.dev","vercel.app","cloudapp.azure.com"
]

def score_subdomain(host: str, dns_res: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0; reasons: List[str] = []
    name_lower = host.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in name_lower]
    if hits:
        score += 2 * min(3, len(hits))  # up to +6
        reasons.append(f"keywords:{','.join(hits)}")
    cname = (dns_res.get("cname") or "").lower()
    if cname:
        for hint in CLOUD_CNAME_HINTS:
            if hint in cname:
                score += 2; reasons.append(f"cname_cloud:{hint}"); break
    ips = dns_res.get("ips", [])
    if any(is_private_ip(ip) for ip in ips):
        score += 3; reasons.append("private_ip")
    if not ips and cname:
        score += 1; reasons.append("cname_no_a")
    if len(hits) >= 2:
        score += 1; reasons.append("multiple_keywords")
    return score, reasons

# ================= Security header helpers =================
def analyze_security_headers(h: Dict[str, str]) -> Dict[str, Any]:
    if not isinstance(h, dict):
        return {"error": str(h)}
    lower = {k.lower(): v for k, v in h.items()}
    res = {k: (k.lower() in lower) for k in SEC_HEADERS}
    notes: List[str] = []
    # HSTS basic check
    hsts = lower.get('strict-transport-security', '')
    if hsts:
        notes.append("HSTS present")
        if 'includesubdomains' not in hsts.lower():
            notes.append("HSTS: consider includeSubDomains")
        if 'preload' not in hsts.lower():
            notes.append("HSTS: consider preload (meets criteria?)")
    else:
        notes.append("Missing HSTS")
    # X-Content-Type-Options
    if lower.get('x-content-type-options','').lower() == 'nosniff':
        notes.append("X-Content-Type-Options: nosniff")
    # CSP quick lints
    csp_val = lower.get('content-security-policy','')
    res['csp_findings'] = csp_lint(csp_val) if csp_val else {"issues": ["Missing CSP"], "policy": ""}
    res['notes'] = notes
    return res

def csp_lint(policy: str) -> Dict[str, Any]:
    issues: List[str] = []
    p = policy.strip()
    by_dir: Dict[str, List[str]] = {}
    for part in [s.strip() for s in p.split(';') if s.strip()]:
        bits = part.split()
        if not bits: continue
        d, srcs = bits[0].lower(), [b.lower() for b in bits[1:]]
        by_dir[d] = srcs
    def has(d, token):
        return token in by_dir.get(d, [])
    # General checks
    for d in ['script-src','style-src']:
        if has(d, "'unsafe-inline'"): issues.append(f"{d}: uses 'unsafe-inline'")
        if has(d, "'unsafe-eval'"): issues.append(f"{d}: uses 'unsafe-eval'")
        if '*' in by_dir.get(d, []): issues.append(f"{d}: wildcard * allowed")
        if not any(s.startswith("'nonce-") or s.startswith("'sha") for s in by_dir.get(d, [])):
            issues.append(f"{d}: missing nonces / hashes or 'strict-dynamic'")
        if 'strict-dynamic' not in by_dir.get(d, []):
            issues.append(f"{d}: consider 'strict-dynamic'")
    if '*' in by_dir.get('connect-src', []): issues.append("connect-src: wildcard *")
    if '*' in by_dir.get('img-src', []): issues.append("img-src: wildcard *")
    if 'object-src' not in by_dir: issues.append("object-src missing (should be 'none')")
    if by_dir.get('object-src') and "'none'" not in by_dir.get('object-src', []): issues.append("object-src not 'none'")
    if 'frame-ancestors' not in by_dir: issues.append("frame-ancestors missing")
    return {"policy": policy, "issues": sorted(set(issues))}

# ================= HTML helpers =================
def extract_hosts_from_html(domain: str, html: str) -> Set[str]:
    hosts: Set[str] = set()
    try:
        for url in HREF_SRC_RE.findall(html or ""):
            try:
                host = urlparse(url).netloc.lower()
                if host and (host.endswith('.' + domain) or host == domain):
                    hosts.add(host)
            except Exception:
                continue
    except Exception:
        pass
    return hosts

def parse_title(html: str) -> str:
    try:
        m = TITLE_RE.search(html or "")
        return re.sub(r"\s+", " ", m.group(1).strip()) if m else ""
    except Exception:
        return ""

# ================= ASN enrichment (Team Cymru whois) =================
def cymru_enrich_ips(ips: List[str], timeout: int = 12) -> Dict[str, Dict[str, str]]:
    """Bulk query whois.cymru.com for IP→ASN/Org. Returns {ip: {asn, prefix, cc, registry, alloc, as_name}}"""
    if not ips:
        return {}
    uniq = sorted({ip for ip in ips if ':' not in ip})  # IPv4 only for this quick path
    if not uniq:
        return {}
    try:
        s = socket.create_connection(("whois.cymru.com", 43), timeout=timeout)
        q = "begin\nverbose\n" + "\n".join(uniq) + "\nend\n"
        s.sendall(q.encode("ascii", errors="ignore"))
        s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(8192)
            if not chunk: break
            data += chunk
        s.close()
        lines = data.decode("utf-8", errors="ignore").splitlines()
        # Expected header: AS|IP|BGP Prefix|CC|Registry|Alloc Date|AS Name
        out: Dict[str, Dict[str, str]] = {}
        for ln in lines:
            if ln.strip().lower().startswith('as|ip|'):  # header
                continue
            parts = [p.strip() for p in ln.split('|')]
            if len(parts) < 7: continue
            asn, ip, prefix, cc, reg, alloc, asname = parts[:7]
            if ip:
                out[ip] = {"asn": asn, "prefix": prefix, "cc": cc, "registry": reg, "alloc": alloc, "as_name": asname}
        return out
    except Exception:
        return {}

# ====== Tech hints from headers/body ======
def infer_tech(headers: Dict[str, str], body: str) -> List[str]:
    hints: Set[str] = set()
    hlower = {f"{k}".lower(): f"{v}".lower() for k,v in headers.items()} if isinstance(headers, dict) else {}
    for name, needles in CDN_HEADER_HINTS:
        if any((n in '\n'.join([f"{k}: {v}" for k,v in hlower.items()])) for n in needles):
            hints.add(name)
    b = body or ""
    for name, needles in TECH_HINTS:
        if any(n.lower() in b.lower() for n in needles):
            hints.add(name)
    return sorted(hints)

# ================= Worker Thread =================
class ReconWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(dict)   # payload with results
    error = pyqtSignal(str)
    # Progress bar signals
    sub_progress_init = pyqtSignal(int)   # total number of subdomains to process
    sub_progress_tick = pyqtSignal(int)   # how many processed so far

    def __init__(self, domain: str, scheme: str, dns_brute: bool, wordlist: Optional[str],
                 probe_http: bool, max_ct: int, max_workers: int,
                 use_sitemaps: bool, fetch_whois: bool, titles_topn: int, asn_enrich: bool):
        super().__init__()
        self.domain = domain.strip()
        self.scheme = scheme
        self.dns_brute = dns_brute
        self.wordlist = wordlist
        self.probe_http = probe_http
        self.max_ct = max_ct
        self.max_workers = max_workers
        self.use_sitemaps = use_sitemaps
        self.fetch_whois = fetch_whois
        self.titles_topn = titles_topn
        self.asn_enrich = asn_enrich

    def log(self, msg: str):
        self.progress.emit(msg)

    def run(self):
        try:
            domain = self.domain
            base = f"{self.scheme}://{domain}"
            out: Dict[str, Any] = {"domain": domain, "sections": {}, "subdomains": []}

            # 1) security.txt
            self.log("Fetching security.txt …")
            sec_url = f"{self.scheme}://{domain}/.well-known/security.txt"
            r = fetch_url(sec_url, "GET")
            if isinstance(r, Exception):
                out["sections"]["security_txt"] = {"url": sec_url, "status": "n/a", "body": f"<error: {r}>"}
            else:
                out["sections"]["security_txt"] = {"url": sec_url, "status": r.status_code, "body": r.text[:20000]}

            # 2) HTTP headers + GET root
            self.log("Collecting HTTP headers for root …")
            rh = fetch_url(base, "HEAD")
            rg = fetch_url(base, "GET")
            def hdrs(resp):
                if isinstance(resp, Exception): return {"error": str(resp)}
                return {k: v for k, v in resp.headers.items()}
            out["sections"]["headers_head"] = hdrs(rh)
            out["sections"]["headers_get"] = hdrs(rg)

            # Analyze security headers & cookies & redirects & title/tech
            if not isinstance(rg, Exception):
                # Redirects chain
                redirects = [{"status": h.status_code, "url": h.url} for h in rg.history]
                out["sections"]["http_root"] = {
                    "final_url": rg.url,
                    "status": rg.status_code,
                    "redirects": redirects,
                    "title": parse_title(rg.text),
                    "techs": infer_tech(out["sections"].get("headers_get", {}), rg.text),
                }
                out["sections"]["security_headers_eval"] = analyze_security_headers(out["sections"].get("headers_get", {}))
                # Cookies (quick)
                cookies = []
                for k, v in out["sections"]["headers_get"].items():
                    if k.lower() == 'set-cookie':
                        for part in str(v).split('\n'):
                            if not part.strip(): continue
                            ck = part
                            flags = {f: (f.lower() in ck.lower()) for f in ["Secure", "HttpOnly", "SameSite=Strict", "SameSite=Lax", "SameSite=None"]}
                            cookies.append({"cookie": ck[:120] + ("…" if len(ck) > 120 else ""), "flags": flags})
                out["sections"]["cookies"] = {"count": len(cookies), "items": cookies}
            else:
                out["sections"]["http_root"] = {"error": str(rg)}
                out["sections"]["security_headers_eval"] = {"error": str(rg)}
                out["sections"]["cookies"] = {"count": 0, "items": []}

            # 3) robots.txt (+ sitemaps)
            self.log("Downloading robots.txt …")
            robots_url = f"{self.scheme}://{domain}/robots.txt"
            r = fetch_url(robots_url, "GET")
            sitemaps: List[str] = []
            if isinstance(r, Exception):
                out["sections"]["robots"] = {"url": robots_url, "status": "n/a", "body": f"<error: {r}>"}
            else:
                body = r.text[:30000]
                out["sections"]["robots"] = {"url": robots_url, "status": r.status_code, "body": body}
                if self.use_sitemaps:
                    for line in body.splitlines():
                        if line.lower().startswith("sitemap:"):
                            sitemaps.append(line.split(":",1)[1].strip())

            added_from_html: Set[str] = set()
            if not isinstance(rg, Exception):
                added_from_html = extract_hosts_from_html(domain, rg.text)

            # 4) TLS info
            self.log("Extracting TLS certificate info …")
            tls = tls_info(domain, 443 if self.scheme == "https" else 80)
            out["sections"]["tls"] = tls

            # 5) DNS overview
            self.log("Resolving basic DNS records …")
            dns_map = basic_dns(domain)
            out["sections"]["dns"] = dns_map

            # 6) Optional WHOIS
            if self.fetch_whois and shutil.which("whois"):
                self.log("Running WHOIS …")
                who = run(["whois", domain], timeout=25)
                out["sections"]["whois"] = who[:40000]

            # 7) Subdomain enumeration (CT + optional brute + hints)
            self.log("Enumerating subdomains via CT …")
            subs_ct = ct_subdomains(domain, max_rows=self.max_ct)
            all_subs: Set[str] = set(subs_ct)
            if self.dns_brute:
                self.log("Performing lightweight DNS brute-force …")
                brute_found = dns_bruteforce(domain, wordlist=self.wordlist, max_workers=self.max_workers)
                all_subs |= brute_found
            # add hosts discovered from HTML
            all_subs |= added_from_html

            # Sitemaps discovery
            hosts_from_sitemaps: Set[str] = set()
            if self.use_sitemaps and sitemaps:
                self.log("Fetching sitemap(s) …")
                for sm in sitemaps[:3]:
                    rr = fetch_url(sm, "GET")
                    if isinstance(rr, Exception) or getattr(rr, 'status_code', 0) != 200:
                        continue
                    try:
                        root = ET.fromstring(rr.text)
                        for loc in root.iter():
                            if loc.tag.endswith('loc') and loc.text:
                                host = urlparse(loc.text).netloc.lower()
                                if host and (host.endswith('.' + domain) or host == domain):
                                    hosts_from_sitemaps.add(host)
                    except Exception:
                        continue
            all_subs |= hosts_from_sitemaps

            self.log(f"Total candidate subdomains: {len(all_subs)}")

            self.log("Detecting wildcard DNS …")
            wildcard, wild_ips = detect_wildcard(domain)

            def process_host(h: str) -> Dict[str, Any]:
                res = resolve_host(h)
                score, reasons = score_subdomain(h, res)
                http_status = ""
                if self.probe_http and self.titles_topn <= 0:
                    # only HEAD probe when we're not fetching titles
                    for sch in ["https", "http"]:
                        try:
                            resp = requests.head(f"{sch}://{h}", timeout=5, allow_redirects=True, verify=False)
                            http_status = f"{sch.upper()} {resp.status_code}"; break
                        except Exception: continue
                row = {"host": h, "ips": res.get("ips", []), "cname": res.get("cname", ""),
                       "score": score, "reasons": reasons, "http": http_status}
                if wildcard and set(row["ips"]) and set(row["ips"]).issubset(set(wild_ips)):
                    row["reasons"].append("wildcard_like"); row["score"] = max(0, row["score"] - 1)
                return row

            resolved_rows: List[Dict[str, Any]] = []
            if all_subs:
                self.log("Resolving and scoring subdomains …")
                total = len(all_subs)
                self.sub_progress_init.emit(total)     # init determinate progress
                with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                    futures = {ex.submit(process_host, h): h for h in sorted(all_subs)}
                    done_count = 0
                    for fut in as_completed(futures):
                        row = fut.result(); resolved_rows.append(row)
                        done_count += 1
                        self.sub_progress_tick.emit(done_count)   # advance bar
                        if done_count % max(1, len(futures)//20) == 0:
                            self.log(f"Progress: {done_count}/{len(futures)} subdomains processed …")
            else:
                # no subs; make the bar jump to done quickly so UI doesn't hang in "Working…"
                self.sub_progress_init.emit(1)
                self.sub_progress_tick.emit(1)

            # Optionally fetch titles for top-N subdomains (active GET)
            titles_info: List[Dict[str, Any]] = []
            if self.titles_topn > 0 and resolved_rows:
                self.log(f"Fetching titles for top {self.titles_topn} subdomains …")
                top_hosts = [r["host"] for r in sorted(resolved_rows, key=lambda r: (-r["score"], r["host"]))[:self.titles_topn]]
                for h in top_hosts:
                    ttl = ""; st = ""
                    for sch in ["https", "http"]:
                        try:
                            rr = requests.get(f"{sch}://{h}", timeout=8, allow_redirects=True, verify=False)
                            ttl = parse_title(rr.text); st = f"{sch.upper()} {rr.status_code}"; break
                        except Exception:
                            continue
                    titles_info.append({"host": h, "title": ttl, "http": st})

            resolved_rows.sort(key=lambda r: (-r["score"], r["host"]))
            out["wildcard"] = {"enabled": wildcard, "ips": wild_ips}
            out["subdomains"] = resolved_rows
            out["sections"]["sitemaps"] = {"urls": sitemaps, "hosts_added": sorted(hosts_from_sitemaps)}
            out["sections"]["html_hosts"] = sorted(added_from_html)
            out["sections"]["titles_top"] = titles_info

            # ASN enrichment over unique IPs (root DNS + subdomains)
            if self.asn_enrich:
                self.log("Enriching IPs with ASN/Org (Team Cymru) …")
                ip_set: Set[str] = set()
                # root DNS A/AAAA lines
                for k,v in out.get('sections',{}).get('dns',{}).items():
                    if k in ("A","AAAA","A/AAAA") and isinstance(v, str):
                        for line in v.splitlines():
                            val = line.strip()
                            if val and all(c in '0123456789.:' for c in val):
                                ip_set.add(val)
                for row in resolved_rows:
                    for ip in row.get('ips', []):
                        ip_set.add(ip)
                asn_map = cymru_enrich_ips(sorted(ip_set))
                out['sections']['asn'] = asn_map

            self.done.emit(out)
        except Exception as e:
            self.error.emit(str(e))

# ================= Main Window =================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Safe Org Recon — Passive GUI (v4.1)")
        self.resize(1220, 800)
        self._apply_dark_theme()

        self.worker: Optional[ReconWorker] = None
        self.results: Optional[Dict[str, Any]] = None
        self._sub_total = 1

        # ---- Controls
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central)

        grid = QGridLayout(); row = 0
        grid.addWidget(QLabel("Domain:"), row, 0)
        self.domain_edit = QLineEdit(); self.domain_edit.setPlaceholderText("example.com")
        grid.addWidget(self.domain_edit, row, 1, 1, 3); row += 1

        grid.addWidget(QLabel("Scheme:"), row, 0)
        self.scheme_https = QCheckBox("https (recommended)"); self.scheme_http = QCheckBox("http")
        self.scheme_https.setChecked(True)
        self.scheme_http.stateChanged.connect(lambda _: self._exclusive_scheme())
        self.scheme_https.stateChanged.connect(lambda _: self._exclusive_scheme())
        hscheme = QHBoxLayout(); hscheme.addWidget(self.scheme_https); hscheme.addWidget(self.scheme_http); hscheme.addStretch(1)
        grid.addLayout(hscheme, row, 1, 1, 3); row += 1

        self.chk_dns_brute = QCheckBox("Enable lightweight DNS brute-force")
        grid.addWidget(self.chk_dns_brute, row, 0, 1, 2)
        self.btn_wordlist = QPushButton("Choose wordlist…"); self.btn_wordlist.clicked.connect(self._choose_wordlist)
        self.wordlist_path = QLineEdit(); self.wordlist_path.setPlaceholderText("(Optional) path to wordlist")
        hwl = QHBoxLayout(); hwl.addWidget(self.btn_wordlist); hwl.addWidget(self.wordlist_path)
        grid.addLayout(hwl, row, 2, 1, 2); row += 1

        self.chk_probe_http = QCheckBox("Probe subdomains with HEAD (idempotent, off by default)")
        grid.addWidget(self.chk_probe_http, row, 0, 1, 4); row += 1

        self.chk_sitemaps = QCheckBox("Discover hosts via sitemap(s)"); self.chk_sitemaps.setChecked(True)
        grid.addWidget(self.chk_sitemaps, row, 0, 1, 2)

        self.chk_whois = QCheckBox("Include WHOIS (if available)"); self.chk_whois.setChecked(False)
        grid.addWidget(self.chk_whois, row, 2, 1, 1)

        self.chk_asn = QCheckBox("Enrich IPs with ASN (Team Cymru)"); self.chk_asn.setChecked(True)
        grid.addWidget(self.chk_asn, row, 3, 1, 1); row += 1

        grid.addWidget(QLabel("Max CT rows:"), row, 0)
        self.spin_ct = QSpinBox(); self.spin_ct.setRange(100, 20000); self.spin_ct.setValue(5000)
        grid.addWidget(self.spin_ct, row, 1)
        grid.addWidget(QLabel("Max workers:"), row, 2)
        self.spin_workers = QSpinBox(); self.spin_workers.setRange(1, 512); self.spin_workers.setValue(60)
        grid.addWidget(self.spin_workers, row, 3); row += 1

        grid.addWidget(QLabel("Fetch titles for top-N subdomains:"), row, 0)
        self.spin_titles = QSpinBox(); self.spin_titles.setRange(0, 100); self.spin_titles.setValue(0)
        grid.addWidget(self.spin_titles, row, 1)
        root.addLayout(grid)

        # ---- Buttons
        hbtn = QHBoxLayout()
        self.btn_run = QPushButton("Run Recon"); self.btn_run.clicked.connect(self._start_recon)
        self.btn_export_md = QPushButton("Save Markdown Report…"); self.btn_export_md.clicked.connect(self._save_md)
        self.btn_export_csv = QPushButton("Export CSV…"); self.btn_export_csv.clicked.connect(self._save_csv)
        self.btn_export_json = QPushButton("Export JSON…"); self.btn_export_json.clicked.connect(self._save_json)
        self.btn_quicksave = QPushButton("Quick Save All"); self.btn_quicksave.setToolTip("Save MD + CSV + JSON (+ DOT/ASN if present) to ~/recon_reports"); self.btn_quicksave.clicked.connect(self._autosave_all)
        hbtn.addWidget(self.btn_run); hbtn.addStretch(1); hbtn.addWidget(self.btn_quicksave); hbtn.addWidget(self.btn_export_md); hbtn.addWidget(self.btn_export_csv); hbtn.addWidget(self.btn_export_json)
        root.addLayout(hbtn)

        # ---- Log output
        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setMinimumHeight(140)
        root.addWidget(self.log)

        # ---- Progress bar (indeterminate until subdomain stage begins)
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setRange(0, 0)              # spinner / marquee
        self.progress.setFormat("Working…")
        root.addWidget(self.progress)

        # ---- Table for subdomains
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Host","Score","Reasons","CNAME","IPs","HTTP"])
        hdr = self.table.horizontalHeader(); hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1,6): hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self.table)

        # Footer note
        self.footer = QLabel("Use only with explicit authorization. Default behavior is passive.")
        self.footer.setAlignment(Qt.AlignmentFlag.AlignRight); root.addWidget(self.footer)

    # ------------- UI Helpers -------------
    def _apply_dark_theme(self):
        self.setStyleSheet(
            """
            QWidget { background-color: #0e1013; color: #e4e7eb; font-size: 13px; }
            QLineEdit, QTextEdit, QTableWidget { background-color: #151821; color: #e4e7eb; border: 1px solid #2a2f3a; }
            QCheckBox, QLabel { color: #e4e7eb; }
            QPushButton { background-color: #243042; border: 1px solid #3b4453; padding: 6px 10px; border-radius: 6px; }
            QPushButton:hover { background-color: #2c3a50; }
            QPushButton:disabled { background-color: #202733; color: #8a8f98; }
            QHeaderView::section { background-color: #1b212d; color: #e4e7eb; border: 0px; padding: 6px; }
            """
        )

    def _exclusive_scheme(self):
        if self.scheme_https.isChecked() and self.scheme_http.isChecked():
            sender = self.sender()
            if sender is self.scheme_https:
                self.scheme_http.setChecked(False)
            else:
                self.scheme_https.setChecked(False)
        elif not self.scheme_https.isChecked() and not self.scheme_http.isChecked():
            self.scheme_https.setChecked(True)

    def _choose_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose wordlist", os.path.expanduser("~"))
        if path: self.wordlist_path.setText(path)

    def _start_recon(self):
        domain = self.domain_edit.text().strip()
        if not domain or "." not in domain:
            QMessageBox.warning(self, "Input", "Please enter a valid domain (e.g., example.com)"); return
        scheme = "https" if self.scheme_https.isChecked() else "http"
        dns_brute = self.chk_dns_brute.isChecked()
        wordlist = self.wordlist_path.text().strip() or None
        probe_http = self.chk_probe_http.isChecked()
        max_ct = self.spin_ct.value(); max_workers = self.spin_workers.value()
        use_sitemaps = self.chk_sitemaps.isChecked(); fetch_whois = self.chk_whois.isChecked()
        titles_topn = self.spin_titles.value(); asn_enrich = self.chk_asn.isChecked()

        self.log.clear(); self._set_controls_enabled(False); self.table.setRowCount(0); self.results = None

        # progress bar: set to indeterminate while setup stages run
        self.progress.setRange(0, 0)
        self.progress.setFormat("Working…")

        self.worker = ReconWorker(domain, scheme, dns_brute, wordlist, probe_http, max_ct, max_workers, use_sitemaps, fetch_whois, titles_topn, asn_enrich)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.error.connect(self._on_error)
        self.worker.sub_progress_init.connect(self._on_subprog_init)
        self.worker.sub_progress_tick.connect(self._on_subprog_tick)
        self.worker.start()

    def _set_controls_enabled(self, enabled: bool):
        for w in [self.domain_edit, self.scheme_https, self.scheme_http, self.chk_dns_brute, self.btn_wordlist,
                  self.wordlist_path, self.chk_probe_http, self.spin_ct, self.spin_workers, self.btn_run,
                  self.btn_export_md, self.btn_export_csv, self.btn_export_json, self.btn_quicksave,
                  self.chk_sitemaps, self.chk_whois, self.spin_titles, self.chk_asn]:
            w.setEnabled(enabled)

    def _on_progress(self, msg: str):
        self.log.append(msg)

    def _on_error(self, err: str):
        self._set_controls_enabled(True)
        # progress bar -> error
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("Error")
        QMessageBox.critical(self, "Error", err)

    def _on_done(self, payload: Dict[str, Any]):
        self._set_controls_enabled(True); self.results = payload
        subs = payload.get("subdomains", []); self.table.setRowCount(len(subs))
        for r, row in enumerate(subs):
            self.table.setItem(r, 0, QTableWidgetItem(row.get("host", "")))
            self.table.setItem(r, 1, QTableWidgetItem(str(row.get("score", 0))))
            self.table.setItem(r, 2, QTableWidgetItem(", ".join(row.get("reasons", []))))
            self.table.setItem(r, 3, QTableWidgetItem(row.get("cname", "")))
            self.table.setItem(r, 4, QTableWidgetItem(", ".join(row.get("ips", []))))
            self.table.setItem(r, 5, QTableWidgetItem(row.get("http", "")))
        self.log.append(f"Finished. {len(subs)} subdomains processed.")
        try:
            saved_paths = self._autosave_all(silent=True)
            if saved_paths: self.log.append("Auto-saved to: " + ", ".join(str(p) for p in saved_paths))
        except Exception as e:
            self.log.append(f"[autosave warning] {e}")

        # Progress: set to 100% and Done
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.progress.setFormat("Done")

    # ----- Progress slots
    def _on_subprog_init(self, total: int):
        if total <= 0:
            total = 1
        self._sub_total = total
        self.progress.setRange(0, total)
        self.progress.setValue(0)
        self.progress.setFormat(f"Resolving subdomains: %p% (0/{total})")

    def _on_subprog_tick(self, current: int):
        total = getattr(self, "_sub_total", 1)
        if current > total:
            current = total
        self.progress.setValue(current)
        self.progress.setFormat(f"Resolving subdomains: %p% ({current}/{total})")

    # ------------- Export Helpers -------------
    def _save_md(self):
        if not self.results:
            QMessageBox.information(self, "Export", "No results to save yet."); return
        path, _ = QFileDialog.getSaveFileName(self, "Save Markdown Report", os.path.expanduser("~"), "Markdown (*.md)")
        if not path: return
        md = self._render_markdown(self.results)
        try:
            with open(path, 'w', encoding='utf-8') as f: f.write(md)
            QMessageBox.information(self, "Export", f"Saved: {path}")
        except PermissionError:
            QMessageBox.critical(self, "Export", "Permission denied. Choose a folder in your home directory, e.g., ~/recon_reports")
        except Exception as e:
            QMessageBox.critical(self, "Export", str(e))

    def _save_csv(self):
        if not self.results:
            QMessageBox.information(self, "Export", "No results to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", os.path.expanduser("~"), "CSV (*.csv)")
        if not path: return
        subs = self.results.get("subdomains", [])
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["host","score","reasons","ips","cname","http"])
                for r in subs:
                    w.writerow([ r.get("host",""), r.get("score",0), ";".join(r.get("reasons",[])),
                                 ",".join(r.get("ips",[])), r.get("cname",""), r.get("http",""), ])
            QMessageBox.information(self, "Export", f"Saved: {path}")
        except PermissionError:
            QMessageBox.critical(self, "Export", "Permission denied. Choose a folder in your home directory, e.g., ~/recon_reports")
        except Exception as e:
            QMessageBox.critical(self, "Export", str(e))

    def _save_json(self):
        if not self.results:
            QMessageBox.information(self, "Export", "No results to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", os.path.expanduser("~"), "JSON (*.json)")
        if not path: return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.results.get("subdomains", []), f, indent=2)
            QMessageBox.information(self, "Export", f"Saved: {path}")
        except PermissionError:
            QMessageBox.critical(self, "Export", "Permission denied. Choose a folder in your home directory, e.g., ~/recon_reports")
        except Exception as e:
            QMessageBox.critical(self, "Export", str(e))

    def _render_redirect_dot(self, http_root: Dict[str, Any]) -> str:
        try:
            if not http_root or 'redirects' not in http_root:
                return ""
            edges = []
            hist = http_root.get('redirects', [])
            prev = None
            if hist:
                prev = hist[0].get('url')
                for nxt in hist[1:]:
                    edges.append((prev, nxt.get('url')))
                    prev = nxt.get('url')
                edges.append((prev, http_root.get('final_url')))
            else:
                return ""
            lines = ["digraph redirects {", "  rankdir=LR;"]
            for a,b in edges:
                if not a or not b: continue
                lines.append(f'  "{a}" -> "{b}";')
            lines.append("}")
            return "\n".join(lines)
        except Exception:
            return ""

    def _render_markdown(self, results: Dict[str, Any]) -> str:
        d = results.get("domain", ""); sec = results.get("sections", {}); wild = results.get("wildcard", {}); subs = results.get("subdomains", [])
        lines: List[str] = []
        lines.append(f"# Organization Recon Report: {d}\n")

        # Root HTTP summary
        http = sec.get("http_root", {})
        lines.append("## Root HTTP Summary")
        if http:
            if 'error' in http:
                lines.append(f"Error: {http['error']}")
            else:
                lines.append(f"Final URL: `{http.get('final_url','')}`  ")
                lines.append(f"Status: {http.get('status','')}")
                if http.get('redirects'):
                    lines.append("Redirects:")
                    for r in http['redirects']:
                        lines.append(f"- {r.get('status')} → `{r.get('url')}`")
                if http.get('title'):
                    lines.append(f"Title: {http['title']}")
                if http.get('techs'):
                    lines.append(f"Tech hints: {', '.join(http['techs'])}")
        lines.append("")

        # security.txt
        st = sec.get("security_txt", {})
        lines.append("## security.txt")
        lines.append(f"URL: `{st.get('url','')}`  ")
        lines.append(f"Status: {st.get('status','')}")
        body = st.get("body", "")
        lines.append("\n```\n" + (body[:2000] if isinstance(body, str) else str(body)) + "\n```\n")

        # headers
        lines.append("## HTTP Security Headers (GET, root)")
        seceval = sec.get("security_headers_eval", {})
        if seceval:
            for k in SEC_HEADERS:
                v = seceval.get(k, False)
                lines.append(f"- {k}: {'✅' if v else '❌'}")
            if seceval.get('notes'):
                lines.append("Notes: " + "; ".join(seceval['notes']))
            cfind = seceval.get('csp_findings', {})
            if cfind:
                lines.append("### CSP quick review")
                if cfind.get('policy'): lines.append("Policy (truncated):\n`````\n" + cfind['policy'][:1200] + "\n`````\n")
                if cfind.get('issues'):
                    lines.append("Issues:")
                    for i in cfind['issues']:
                        lines.append(f"- {i}")
        lines.append("")

        # cookies
        ck = sec.get("cookies", {})
        lines.append("## Cookies (Set-Cookie)")
        lines.append(f"Count: {ck.get('count',0)}")
        for item in ck.get('items', [])[:10]:
            lines.append(f"- `{item['cookie']}`  ")
            flags = ", ".join([k for k,v in item.get('flags',{}).items() if v])
            if flags:
                lines.append("  " + flags)
        lines.append("")

        # robots & sitemaps
        rb = sec.get("robots", {})
        lines.append("## robots.txt")
        lines.append(f"URL: `{rb.get('url','')}`  ")
        lines.append(f"Status: {rb.get('status','')}")
        rbb = rb.get('body','')
        lines.append("\n```\n" + (rbb[:2000] if isinstance(rbb, str) else str(rbb)) + "\n```\n")
        sm = sec.get("sitemaps", {})
        if sm.get('urls') or sm.get('hosts_added'):
            lines.append("### Sitemaps")
            if sm.get('urls'):
                lines.append("Declared sitemap URLs:")
                for u in sm['urls']:
                    lines.append(f"- {u}")
            if sm.get('hosts_added'):
                lines.append("Hosts extracted from sitemaps:")
                for h in sm['hosts_added']:
                    lines.append(f"- {h}")
        html_hosts = sec.get('html_hosts', [])
        if html_hosts:
            lines.append("### Hosts spotted in page HTML (href/src)")
            for h in html_hosts:
                lines.append(f"- {h}")
        lines.append("")

        # tls
        lines.append("## TLS Certificate (root)\n```")
        tls_sec = sec.get("tls", {})
        lines.append(json.dumps(tls_sec, indent=2))
        lines.append("```\n")

        # dns
        lines.append("## DNS Records (root)\n```")
        for k, v in sec.get("dns", {}).items():
            lines.append(f"{k}:\n{v}")
        lines.append("```\n")

        # whois
        if sec.get("whois"):
            lines.append("## WHOIS (truncated)\n```")
            lines.append(str(sec.get("whois"))[:4000])
            lines.append("```\n")

        # titles
        tt = sec.get("titles_top", [])
        if tt:
            lines.append("## Titles for top subdomains")
            for item in tt:
                lines.append(f"- `{item.get('host')}` → {item.get('http','')} — {item.get('title','')}")
            lines.append("")

        # ASN
        asn = sec.get('asn', {})
        if asn:
            lines.append("## ASN / Organization (Team Cymru)")
            lines.append("| IP | ASN | BGP Prefix | CC | Registry | Alloc Date | AS Name |")
            lines.append("|---|---:|---|---|---|---|---|")
            for ip, row in sorted(asn.items()):
                lines.append(f"| `{ip}` | {row.get('asn','')} | `{row.get('prefix','')}` | {row.get('cc','')} | {row.get('registry','')} | {row.get('alloc','')} | {row.get('as_name','').replace('|',' ')} |")
            lines.append("")

        # Redirect graph (DOT)
        dot = self._render_redirect_dot(http)
        if dot:
            lines.append("## Redirect Chain (Graphviz DOT)")
            lines.append("```dot\n" + dot + "\n```")

        # subdomains
        lines.append("## Subdomain Enumeration")
        lines.append(f"Wildcard DNS: **{wild.get('enabled', False)}**  " + (f"IPs: {', '.join(wild.get('ips', []))}" if wild.get('ips') else ""))
        lines.append("\n### Top suspicious subdomains (by score)\n")
        if not subs:
            lines.append("_No subdomains resolved._\n")
        else:
            lines.append("| Rank | Host | Score | Reasons | CNAME | IPs | HTTP |")
            lines.append("|---:|---|---:|---|---|---|---|")
            TOPN = min(25, len(subs))
            for i, r in enumerate(subs[:TOPN], 1):
                reasons = ", ".join(r.get("reasons", []))
                ips = ", ".join(r.get("ips", []))
                lines.append(f"| {i} | `{r.get('host','')}` | {r.get('score',0)} | {reasons} | `{r.get('cname','')}` | `{ips}` | {r.get('http','')} |")
        lines.append("\n_This report is generated by a passive recon tool. Use within your authorization and ROE._\n")
        return "\n".join(lines)

    def _autosave_all(self, silent: bool = False):
        """Save MD + CSV + JSON (+ DOT/ASN if present) to ~/recon_reports. Returns list of Paths."""
        if not self.results:
            if not silent:
                QMessageBox.information(self, "Save", "No results to save yet.")
            return []
        domain = self.results.get("domain", "report")
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        outdir = Path.home() / "recon_reports"
        outdir.mkdir(parents=True, exist_ok=True)
        base = outdir / f"{domain}_{ts}"

        saved = []
        # Markdown
        try:
            md = self._render_markdown(self.results)
            md_path = base.with_suffix('.md')
            md_path.write_text(md, encoding='utf-8')
            saved.append(md_path)
        except Exception as e:
            if not silent:
                QMessageBox.critical(self, "Save", f"Markdown save failed: {e}")
        # CSV (subdomains)
        try:
            subs = self.results.get("subdomains", [])
            csv_path = base.with_suffix('.csv')
            with csv_path.open('w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["host","score","reasons","ips","cname","http"])
                for r in subs:
                    w.writerow([
                        r.get("host",""), r.get("score",0), ";".join(r.get("reasons",[])), ",".join(r.get("ips",[])), r.get("cname",""), r.get("http",""),
                    ])
            saved.append(csv_path)
        except Exception as e:
            if not silent:
                QMessageBox.critical(self, "Save", f"CSV save failed: {e}")
        # JSON (subdomains)
        try:
            json_path = base.with_suffix('.json')
            json_path.write_text(json.dumps(self.results.get("subdomains", []), indent=2), encoding='utf-8')
            saved.append(json_path)
        except Exception as e:
            if not silent:
                QMessageBox.critical(self, "Save", f"JSON save failed: {e}")
        # DOT (redirect graph)
        try:
            http_root = self.results.get('sections',{}).get('http_root', {})
            dot = self._render_redirect_dot(http_root)
            if dot:
                dot_path = base.with_suffix('.redirects.dot')
                dot_path.write_text(dot, encoding='utf-8')
                saved.append(dot_path)
        except Exception as e:
            if not silent:
                QMessageBox.warning(self, "Save", f"DOT save warning: {e}")
        # ASN CSV (if any)
        try:
            asn = self.results.get('sections',{}).get('asn', {})
            if asn:
                asn_path = base.with_suffix('.asn.csv')
                with asn_path.open('w', newline='', encoding='utf-8') as f:
                    w = csv.writer(f)
                    w.writerow(["ip","asn","prefix","cc","registry","alloc","as_name"])
                    for ip, row in sorted(asn.items()):
                        w.writerow([ip, row.get('asn',''), row.get('prefix',''), row.get('cc',''), row.get('registry',''), row.get('alloc',''), row.get('as_name','')])
                saved.append(asn_path)
        except Exception as e:
            if not silent:
                QMessageBox.warning(self, "Save", f"ASN save warning: {e}")

        if not silent:
            if saved:
                QMessageBox.information(self, "Save", "Saved:\n" + "\n".join(str(p) for p in saved))
            else:
                QMessageBox.warning(self, "Save", "Nothing was saved.")
        return saved

# ================= Entrypoint =================
def main():
    app = QApplication(sys.argv)
    win = MainWindow(); win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
