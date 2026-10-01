#!/usr/bin/env python3
"""
Bug Bounty Report Analyzer
--------------------------
Parses the recon HTML report, extracts subdomains / URLs / parameters,
classifies potential vulnerabilities, and emits:
  - findings.json   (structured data)
  - final_report.html (self-contained report)
"""

import re, json, html
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter, defaultdict
from pathlib import Path

INPUT        = "Bug_Bounty_Report.html"
OUT_JSON     = "findings.json"
OUT_HTML     = "final_report.html"

# ---------- helpers ---------------------------------------------------------
def load(path):
    return Path(path).read_text(encoding="utf-8", errors="ignore")

def extract_subdomains(doc):
    block = re.search(r'<ul id="listSubs">(.*?)</ul>', doc, re.S)
    if not block: return []
    return re.findall(r'<li>(.*?)</li>', block.group(1))

def extract_urls(doc):
    block = re.search(r'<ul id="listUrls">(.*?)</ul>', doc, re.S)
    if not block: return []
    return re.findall(r'href="([^"]+)"', block.group(1))

def extract_stats(doc):
    cards = re.findall(r'<div class="stat-card"><h3>(.*?)</h3><p>(.*?)</p>', doc)
    return {k.strip(): v.strip() for k, v in cards}

def strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', s)

# ---------- analysis --------------------------------------------------------
INTERESTING_PATTERNS = {
    "open_redirect":      re.compile(r'netsoltrademark\.php\?d=|/redirect|/r\?url=|\?url='),
    "wp_signup":          re.compile(r'wp-signup\.php|wp-login\.php|xmlrpc\.php'),
    "well_known":         re.compile(r'\.well-known/(openid-configuration|ai-plugin\.json|assetlinks\.json|security\.txt|trust\.txt|gpc\.json|dnt-policy\.txt|nodeinfo)'),
    "sitemap":            re.compile(r'sitemap[^" ]*\.xml'),
    "next_image":         re.compile(r'/_next/image\?url='),
    "rsc":                re.compile(r'[?&]_rsc='),
    "tracker":            re.compile(r'/px\.js\?ch=\d'),
    "wp_media":           re.compile(r'/__media__/'),
    "order_id":           re.compile(r'order_id=(\d+)'),
    "deep_link_params":   re.compile(r'(af_xp=|af_force_deeplink=|shortlink=|deep_link_value=|pid=)'),
    "undefined_js":       re.compile(r'undefined\.js'),
    "cdn_url_param":      re.compile(r'cdn\.district\.in/[^"\s]+(&|%26)url=https?[:/]'),
    "admin_panels":       re.compile(r'(admin|accred|stats|mesh|partners|queue)\.district\.in'),
    "mailers":            re.compile(r'mailers\.district\.in'),
    "sensitive_ext":      re.compile(r'\.(env|bak|old|sql|log|git|DS_Store|swp)$'),
    "legacy_assets":      re.compile(r'2015\.css|common2015|details2015'),
}

SEVERITY = {
    "open_redirect":    ("Medium",   "Open Redirect / URL Redirection"),
    "wp_signup":        ("Medium",   "WordPress Signup / CMS Exposure"),
    "well_known":       ("Info",     "Well-Known / Discovery Endpoints"),
    "sitemap":          ("Info",     "Sitemap Disclosure"),
    "next_image":       ("Medium",   "Next.js Image Optimizer SSRF/DoS Surface"),
    "rsc":              ("Info",     "Next.js RSC Payload Parameter"),
    "tracker":          ("Info",     "Tracking Pixel"),
    "wp_media":         ("Medium",   "WordPress __media__ Path (Netsol Trademark)"),
    "order_id":         ("Medium",   "Order ID Exposure (IDOR Candidate)"),
    "deep_link_params": ("Low",      "AppsFlyer Deep-Link Parameters Leaked"),
    "undefined_js":     ("Low",      "Broken / Undefined JS References"),
    "cdn_url_param":    ("Medium",   "CDN URL Parameter Injection"),
    "admin_panels":     ("High",     "Admin / Internal Panels Publicly Reachable"),
    "mailers":          ("Low",      "Mailer Subdomain Disclosure"),
    "sensitive_ext":    ("High",     "Sensitive File Extension"),
    "legacy_assets":    ("Low",      "Legacy Asset Exposure"),
}

def analyze(urls, subs):
    findings = defaultdict(set)

    for u in urls:
        u_clean = strip_ansi(u)
        for tag, pat in INTERESTING_PATTERNS.items():
            if pat.search(u_clean):
                findings[tag].add(u_clean)

    # hidden subdomains not present in the declared subdomain list
    declared = {s.lower().strip() for s in subs}
    hidden = set()
    for u in urls:
        try:
            host = urlparse(strip_ansi(u)).hostname or ""
            if host.endswith(".district.in") and host not in declared:
                hidden.add(host)
        except Exception:
            pass

    # parameter frequency across URLs
    params = Counter()
    for u in urls:
        try:
            q = urlparse(strip_ansi(u)).query
            for k in parse_qs(q):
                params[k] += 1
        except Exception:
            pass

    return findings, hidden, params

# ---------- rendering -------------------------------------------------------
def render(findings, hidden, params, stats, subs):
    def esc(x): return html.escape(str(x))

    rows = []
    for tag, items in sorted(findings.items()):
        sev, title = SEVERITY.get(tag, ("Info", tag))
        badge = f'<span class="badge {sev.lower()}">{sev}</span>'
        samples = "\n".join(f"<li>{esc(u)}</li>" for u in list(items)[:25])
        rows.append(f"""
        <div class="section">
          <h2>{badge} {esc(title)} <small>({len(items)} hits)</small></h2>
          <ul class="evidence">{samples}</ul>
        </div>""")

    hidden_html = "\n".join(f"<li>{esc(h)}</li>" for h in sorted(hidden))
    params_html = "\n".join(
        f"<li><b>{esc(k)}</b> — {v} occurrences</li>"
        for k, v in params.most_common(40)
    )

    cards = "".join(
        f'<div class="stat-card"><h3>{esc(v)}</h3><p>{esc(k)}</p></div>'
        for k, v in stats.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Final Bug Bounty Report — district.in</title>
<style>
:root{{--bg:#0f1115;--card:#1a1d23;--text:#d4d4d4;--accent:#569cd6;--green:#4ec9b0;--red:#f44747;--orange:#ce9178;--yellow:#dcdcaa}}
*{{box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);margin:0;padding:24px;line-height:1.6}}
.container{{max-width:1100px;margin:auto}}
h1{{color:var(--accent);border-bottom:2px solid #333;padding-bottom:8px}}
h2{{color:var(--accent);border-bottom:1px solid #333;padding-bottom:6px;font-size:1.1em}}
small{{color:#888;font-weight:normal}}
.dashboard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:24px 0}}
.stat-card{{background:var(--card);padding:18px;border-radius:8px;text-align:center;border-left:4px solid var(--accent)}}
.stat-card h3{{margin:0;font-size:1.8em;color:var(--green);border:none;padding:0}}
.stat-card p{{margin:4px 0 0;font-size:.85em;color:#888}}
.section{{background:var(--card);padding:18px;border-radius:8px;margin-bottom:16px}}
ul{{padding-left:20px;font-family:'Courier New',monospace;font-size:13px;max-height:320px;overflow:auto}}
li{{word-break:break-all;border-bottom:1px solid #262a31;padding:3px 0}}
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.75em;font-weight:bold;color:#000;margin-right:8px;vertical-align:middle}}
.badge.critical{{background:#ff4d4d}}.badge.high{{background:#ff8c42}}
.badge.medium{{background:#dcdcaa}}.badge.low{{background:#4ec9b0}}.badge.info{{background:#569cd6;color:#fff}}
footer{{color:#666;text-align:center;margin-top:40px;font-size:.85em}}
</style></head><body><div class="container">
<h1>🐛 Final Bug Bounty Report — district.in (Clearme)</h1>
<p>Auto-generated from recon output. Severities are indicative and must be validated against in-scope rules.</p>
<div class="dashboard">{cards}</div>

<div class="section">
  <h2>🔎 Undisclosed Subdomains Found in URLs</h2>
  <p>Hosts observed in URL evidence but <b>missing from the declared subdomain list</b> — verify scope and expand monitoring.</p>
  <ul>{hidden_html or '<li>None</li>'}</ul>
</div>

<div class="section">
  <h2>🧪 Top Parameters Observed</h2>
  <ul>{params_html or '<li>None</li>'}</ul>
</div>

<h2 style="margin-top:32px">🚨 Findings</h2>
{''.join(rows)}

<div class="section">
  <h2>🛡️ Remediation Summary</h2>
  <ol>
    <li><b>Open redirect / netsoltrademark.php:</b> remove the legacy WordPress <code>__media__</code> directory; enforce an allow-list on <code>d=</code>.</li>
    <li><b>wp-signup.php on port 80:</b> disable signups, force HTTPS, block direct port-80 access.</li>
    <li><b>Admin / queue / mesh / stats panels:</b> place behind VPN, IP allow-list, or SSO + MFA.</li>
    <li><b>Order ID in deep links:</b> replace sequential IDs with UUIDs; enforce authorization checks server-side (IDOR).</li>
    <li><b>Next.js <code>/_next/image?url=</code>:</b> restrict the remote-host allow-list, disable on public edge if unused.</li>
    <li><b>CDN URL param injection:</b> sanitize <code>&amp;url=</code> at the CDN edge; strip unknown query params.</li>
    <li><b>.well-known disclosure:</b> audit each file, remove <code>ai-plugin.json</code> if unused, keep only <code>security.txt</code>.</li>
    <li><b>Legacy 2015 assets / undefined.js:</b> remove or 410-gone stale paths.</li>
    <li><b>Mailer subdomains:</b> ensure SPF/DKIM/DMARC alignment to prevent spoofing.</li>
  </ol>
</div>

<footer>Generated by analyze_report.py — review before submission.</footer>
</div></body></html>"""

# ---------- main ------------------------------------------------------------
def main():
    doc = load(INPUT)
    subs = extract_subdomains(doc)
    urls = extract_urls(doc)
    stats = extract_stats(doc)

    findings, hidden, params = analyze(urls, subs)

    payload = {
        "stats": stats,
        "subdomains": subs,
        "hidden_subdomains": sorted(hidden),
        "top_parameters": params.most_common(50),
        "findings": {k: sorted(v) for k, v in findings.items()},
    }
    Path(OUT_JSON).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    Path(OUT_HTML).write_text(render(findings, hidden, params, stats, subs), encoding="utf-8")
    print(f"[+] Wrote {OUT_JSON} and {OUT_HTML}")
    print(f"[+] Findings categories: {list(findings)}")
    print(f"[+] Hidden subdomains: {sorted(hidden)}")

if __name__ == "__main__":
    main()
