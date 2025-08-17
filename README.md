# DC404-Passive-scanner
Passive, compliance-friendly organizational recon with a modern GUI. Designed for authorized security testing and asset inventory.

<img width="1024" height="1024" alt="ChatGPT Image Aug 16, 2025, 07_58_15 PM" src="https://github.com/user-attachments/assets/d9312a4a-6579-4b07-8618-4f4df66eba9b" />

<img width="1920" height="1080" alt="scannertool" src="https://github.com/user-attachments/assets/73aaa484-2d77-4939-acc7-c921e819c258" />


✨ Features

Passive by default

security.txt, robots.txt (+ sitemap host discovery)

Root page HEAD/GET: headers, redirect chain, title, cookie flags

Security header review (HSTS, CSP, X-CTO, etc.) + CSP quick lint

TLS certificate metadata (issuer/subject/validity)

DNS overview (A/AAAA/MX/TXT/NS/SOA) + SPF/DMARC summary

Subdomain discovery

Certificate Transparency (crt.sh)

Optional lightweight DNS bruteforce (wordlist)

Wildcard DNS detection

Suspiciousness scoring (keywords, cloud CNAMEs, private IPs, etc.)

Enrichment (optional)

WHOIS (if whois is on PATH)

ASN/Org for IPs via Team Cymru whois

Optional titles for top-N subdomains

Exports & UX

Markdown report + CSV/JSON of subdomains

DOT graph of redirect chain

Autosave all artifacts to ~/recon_reports/

Progress bar: spins during setup → determinate during subdomain processing

⚠️ Legal & Ethics

Use only on assets where you have explicit, written authorization and a Rules of Engagement (RoE).
The tool avoids destructive actions and defaults to passive collection, but you are responsible for using it lawfully.

🚀 Quick Start
1) Requirements

Python 3.9+

Packages:
pip install PyQt6 requests

Optional system tools (improve results if present):

dig (package: dnsutils) – faster DNS lookups

whois – WHOIS enrichment

Example (Debian/Ubuntu/Parrot):
sudo apt update
sudo apt install -y dnsutils whois

2) Run- python3 safe_org_recon_gui_v4.py
First run on Linux? If you hit a Qt/X11 plugin error, install common XCB deps:sudo apt install -y libxcb-cursor0 libxkbcommon-x11-0

🖱️ Using the GUI

Domain: enter a target like example.com.

Scheme: https (recommended) or http.

Options:

Enable lightweight DNS brute-force
Optionally select a wordlist file (e.g., common subdomains). If you don’t, a small built-in list is used.

Probe subdomains with HEAD
Sends a HEAD request to discovered hosts (idempotent). Off by default.

Discover hosts via sitemap(s)
Parses robots.txt → sitemap URLs → extract same-domain hosts.

Include WHOIS (if available)

Enrich IPs with ASN (Team Cymru)

Fetch titles for top-N subdomains (active GETs for top suspicious hosts).

Click Run Recon.

Watch the log and progress bar (spinner during setup → percentage during subdomain processing).

Save results:

Quick Save All → writes MD + CSV + JSON (+ .redirects.dot / .asn.csv if present) to ~/recon_reports/.

Or use Save Markdown… / Export CSV… / Export JSON… to choose a path.

📦 Outputs

YYYYMMDD-HHMMSS timestamped files under ~/recon_reports/:

acme.com_20250816-121314.md — human-readable report

acme.com_20250816-121314.csv — subdomains (host, score, reasons, ips, cname, http)

acme.com_20250816-121314.json — subdomains (structured)

acme.com_20250816-121314.redirects.dot — Graphviz DOT (redirect chain), if any

acme.com_20250816-121314.asn.csv — ASN enrichment (if enabled)

Subdomain scoring (overview)

Keyword hits: dev, staging, internal, grafana, vpn, sso, db, etc.

Cloud CNAME hints: cloudfront.net, s3.amazonaws.com, azureedge.net, etc.

Private IPs: subdomain resolves to RFC1918 → higher risk score.

CNAME without A/AAAA: slight bump (potential dangling record).

Wildcard-like: score reduced (noise control).

Tip: Sort by Score in the table to review the riskiest candidates first.

🧠 What’s Collected (and why)

security.txt — contacts & disclosure policy

robots.txt / sitemaps — surface area & hints of hidden paths/domains

HTTP headers — security posture, CDN, tech hints

Cookies — Secure, HttpOnly, SameSite flags at a glance

CSP lint — quick smell test for wildcards / unsafe-* / missing directives

TLS cert — validity window, issuer/subject

DNS — mail posture (SPF/DMARC), nameservers, potential misconfigs

CT logs — historical issuance often reveals forgotten subdomains

ASN — ownership & network context for IPs

🔧 Troubleshooting

“No module named PyQt6”
pip install PyQt6 (consider a venv: python3 -m venv venv && source venv/bin/activate)

Qt XCB plugin error on Linux
sudo apt install -y libxcb-cursor0 libxkbcommon-x11-0

Permission denied when saving
Save under your home (default autosave does this). Avoid system directories.

No subdomains found
Increase Max CT rows, enable sitemaps, or add a better wordlist for brute-force.

Slow resolution
Lower Max workers if your resolver rate-limits; or run on a network with better DNS latency.

🧪 Example CLI Wordlists

Open-source lists like subdomains-top1million-110000.txt or curated org-specific lists work well.
Usage: click Choose wordlist… and select the file.

🔒 Security Notes

The app disables TLS verification (verify=False) for collection resilience across misconfigured hosts.
Data is read-only; no credentials are sent. If you require strict TLS, I can add a toggle.

HEAD/GET probes are limited and user-controlled.

CT queries and Team Cymru whois are public services; rate limits may apply.

🗺️ Roadmap (nice-to-haves)

Export to Excel (XLSX) with filters & conditional formatting

Regex filters + quick find in the table

Overall stage progress (weighted %) alongside subdomain bar

Optional strict TLS mode

🧩 Changelog

v4.1

Added determinate progress bar for subdomain processing

Improved autosave reliability and error messaging

Added CSP quick lint & expanded header notes

ASN enrichment export (.asn.csv)

Redirect chain DOT export

v4.0

Unified GUI + Passive recon core + Autosave

🤝 Contributing

Issues and PRs welcome!
Please avoid adding active scanning modules without rate-limit controls and clear UI warnings.


🧭 Attribution

This tool queries public services (e.g., crt.sh, Team Cymru whois). Respect their acceptable use and rate limits.
