import os, re, io, csv, socket, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

import requests
from flask import Flask, request, render_template_string, send_file, url_for
from jinja2 import DictLoader

# ==========================
# App config
# ==========================
APP_NAME = "Ads.txt Crawler"
STATIC_REV = os.environ.get("STATIC_REV", "3")

ALLOWED_EMAILS = {e.strip().lower() for e in (
    os.environ.get("ALLOWED_EMAILS")
    or "mgaudencio@yieldmo.com,rnjoku@yieldmo.com,puppalapati@yieldmo.com"
).split(",")}
# Only for testing a direct run.app URL without IAP (set to "1" to enable)
DEV_ALLOW_NO_IAP = os.environ.get("DEV_ALLOW_NO_IAP") == "1"

MAX_BYTES    = 1024 * 1024
HTTP_TIMEOUT = 10
MAX_ROWS     = 1000
MAX_WORKERS  = 40
USER_AGENT   = os.environ.get("CRAWLER_UA", "Mozilla/5.0; ads-txt-checker/1.2")
ALLOW_INSECURE_SSL = os.environ.get("ALLOW_INSECURE_SSL") == "1"  # default False

# Optional lines to verify presence in files
REQUIRED_LINES = [
    {"label": "TrustedStack (trustedstack.com, TS931XQ4D, DIRECT)",
     "needle": "trustedstack.com, TS931XQ4D, DIRECT"},
    {"label": "OpenX Yieldmo (openx.com, 558228330, RESELLER, 6a698e2ec38604c6)",
     "needle": "openx.com, 558228330, RESELLER, 6a698e2ec38604c6"},
]

# ==========================
# Flask + basic hardening
# ==========================
app = Flask(__name__)

@app.after_request
def set_security_headers(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/healthz")
def healthz():
    return "ok", 200

def iap_email():
    raw = request.headers.get("X-Goog-Authenticated-User-Email", "")
    return raw.split(":", 1)[-1].lower() if ":" in raw else raw.lower()

def require_iap_and_allowlist():
    email = iap_email()
    if not email and DEV_ALLOW_NO_IAP:
        email = "dev@local"
    if email not in ALLOWED_EMAILS:
        return None, ("Access denied", 403)
    return email, None

# ==========================
# SSRF guard + validators
# ==========================
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$")
PRIVATE_NETS = [
    ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"), ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"), ip_network("::1/128"),
    ip_network("fc00::/7"), ip_network("fe80::/10"),
]
BLOCKED_HOSTS = {"metadata.google.internal", "169.254.169.254"}

def is_private_or_blocked(host: str) -> bool:
    if not host or host in BLOCKED_HOSTS:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
        ips = {i[4][0] for i in infos}
        for ip in ips:
            if any(ip_address(ip) in net for net in PRIVATE_NETS):
                return True
    except Exception:
        return True
    return False

def clean_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = d.replace("http://", "").replace("https://", "")
    return d.split("/")[0]

def normalize_kind(val: str) -> str:
    v = (val or "").strip().lower().replace("-", "_").replace(" ", "_")
    if v in ("app", "apps", "app_ads", "appads", "in_app", "mobile_app"):
        return "app"
    return "ads"

def urls_for(domain: str, kind: str):
    d = clean_domain(domain)
    if not d or not DOMAIN_RE.match(d) or is_private_or_blocked(d):
        raise ValueError("Invalid or blocked domain")
    path = "app-ads.txt" if kind == "app" else "ads.txt"
    return [f"https://{d}/{path}", f"http://{d}/{path}"]

def explain_status(status: str) -> str:
    if status == "Present": return "Publisher ID is listed"
    if status == "Not Present": return "File found; publisher ID not listed"
    if status.startswith("HTTP "): return status
    if status.startswith("Error"): return "All attempts failed – SSL/timeout/other"
    if status == "Invalid Domain": return "Domain blank/malformed/blocked"
    return "Unknown"

# ==========================
# Fetch
# ==========================
def fetch_once(domain: str, publisher_id: str, kind: str):
    publisher_id = str(publisher_id or "")
    kind = normalize_kind(kind)
    try:
        url_list = urls_for(domain, kind)
    except ValueError:
        return {"domain": clean_domain(domain), "publisher_id": publisher_id, "kind": kind,
                "status": "Invalid Domain", "sample": "", "url": "", "bytes": 0, "status_code": 0,
                "required": {r["label"]: "" for r in REQUIRED_LINES}}
    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain"}
    for url in url_list:
        try:
            r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, verify=not ALLOW_INSECURE_SSL)
            if r.status_code == 200:
                txt = r.text
                sample = ""
                for line in txt.splitlines():
                    core = line.split("#", 1)[0].strip()
                    if publisher_id and publisher_id in core:
                        sample = line.strip()
                        break
                status = "Present" if sample else "Not Present"
                req = {}
                low = txt.lower()
                for item in REQUIRED_LINES:
                    req[item["label"]] = "Yes" if item["needle"].lower() in low else "No"
                return {"domain": clean_domain(domain), "publisher_id": publisher_id, "kind": kind,
                        "status": status, "sample": sample, "url": url,
                        "bytes": len(txt.encode("utf-8")), "status_code": 200, "required": req}
            else:
                return {"domain": clean_domain(domain), "publisher_id": publisher_id, "kind": kind,
                        "status": f"HTTP {r.status_code}", "sample": "", "url": url,
                        "bytes": 0, "status_code": r.status_code,
                        "required": {r["label"]: "" for r in REQUIRED_LINES}}
        except requests.RequestException:
            continue
    return {"domain": clean_domain(domain), "publisher_id": publisher_id, "kind": kind,
            "status": "Error: Could not fetch ads.txt/app-ads.txt", "sample": "",
            "url": " and ".join(url_list), "bytes": 0, "status_code": 0,
            "required": {r["label"]: "" for r in REQUIRED_LINES}}

# ==========================
# CSV parsing (flex headers)
# ==========================
def _lc_keys(d: dict) -> dict:
    return {(k.strip().lower() if isinstance(k, str) else k): v for k, v in d.items()}

def _host_from_value(val: str) -> str:
    s = str(val or "").strip()
    if not s: return ""
    if s.startswith(("http://", "https://")):
        try: return (urlparse(s).hostname or "").lower()
        except Exception: return ""
    if "." in s and " " not in s: return s.lower()
    return ""

def _infer_kind(inv: str, default_kind: str) -> str:
    v = (inv or "").strip().lower().replace("-", "_").replace(" ", "_")
    if v in {"app", "in_app", "apps", "app_ads", "appads", "mobile_app"}: return "app"
    if v in {"mobile_web", "mobileweb", "web", "site"}: return "ads"
    return normalize_kind(default_kind)

PUB_ID_KEYS = {
    "publisher & placement publisher id", "publisher_id", "publisher id", "pub_id",
    "seller_id", "seller id", "account_id", "account id", "account"
}
APP_DOMAIN_KEYS = {
    "supply app supply app domain", "supply app domain", "app domain", "app_domain",
    "developer domain", "developer_domain"
}
URL_OR_DOMAIN_KEYS = {
    "exchange measurements bundle id or page url", "bundle id or page url", "page url",
    "site url", "domain", "root domain", "web domain", "site", "page", "url"
}
INV_TYPE_KEYS = {"publisher & placement inventory type", "inventory type", "inventory_type"}

def _first_from(row: dict, keys: set[str]) -> str:
    for k in keys:
        if k in row:
            v = str(row.get(k) or "").strip()
            if v: return v
    return ""

def row_to_triplet_auto(raw_row: dict, default_kind: str):
    row = _lc_keys(raw_row)
    pub_id = _first_from(row, PUB_ID_KEYS)
    if not pub_id:
        return ("", "", "", "missing publisher_id")
    inv = _first_from(row, INV_TYPE_KEYS)
    kind = _infer_kind(inv, default_kind)
    if kind == "app":
        domain = _first_from(row, APP_DOMAIN_KEYS)
        if not domain:
            urlish = _first_from(row, URL_OR_DOMAIN_KEYS)
            domain = _host_from_value(urlish)
        if not domain:
            return ("", "", "", "app row missing Supply App Domain (or URL host)")
    else:
        urlish = _first_from(row, URL_OR_DOMAIN_KEYS)
        domain = _host_from_value(urlish)
        if not domain:
            return ("", "", "", "web row missing domain or URL")
    return (domain, pub_id, kind, "")

def parse_pairs(text, default_kind):
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line: continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2:
            d, p = parts[0], parts[1]
            k = parts[2] if len(parts) >= 3 else default_kind
            out.append((d, p, k))
    return out

# ==========================
# Templates
# ==========================
BASE_HTML = """<!doctype html><html lang='en'><head>
<meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>{{ app_name }}</title>
<link rel='icon' href='{{ url_for("static", filename="favicon.svg") }}' type='image/svg+xml'>
<link rel='stylesheet' href='{{ url_for("static", filename="style.css") }}'>
</head>
<body>
<div class='wrap'>
  <header class='site-header'>
    <div class='brand'>
      <img class='brand-logo' src='{{ url_for("static", filename="logo.png") }}' alt='Logo' />
      <h1>{{ app_name }}</h1>
    </div>
    <div class='right'>
      <nav>
        <a href='/' class='{{ "active" if active=="single" else "" }}'>Single</a>
        <a href='/crawler' class='{{ "active" if active=="crawler" else "" }}'>Crawler</a>
      </nav>
      {% if user_email %}<span class='pill'>{{ user_email }}</span>{% endif %}
    </div>
  </header>

  <main class='card'>{% block content %}{% endblock %}</main>
  <div class='footer small'>IAP-only • No storage</div>
</div>
</body></html>"""

INDEX_HTML = """{% extends 'base.html' %}{% block content %}
  <h2 class="mt0">Quick check</h2>
  <form method='POST' action='/check'>
    <div class="grid2">
      <div>
        <label>Type</label>
        <select name='kind'><option value='ads'>ads.txt (domain)</option><option value='app'>app-ads.txt (app)</option></select>
      </div>
      <div>
        <label>Publisher ID</label>
        <input type='text' name='publisher_id' placeholder='pub-… or numeric ID' required />
      </div>
    </div>
    <label class="mt8">Domain or URL (or app domain)</label>
    <input type='text' name='domain' placeholder='example.com  |  https://example.com/ads.txt' required />
    <div class="mt12"><button type='submit'>Check</button></div>
  </form>
{% endblock %}"""

RESULTS_HTML = """{% extends 'base.html' %}{% block content %}
  <h2 class="mt0">Result</h2>
  <div class="table-scroll h240">
    <table class="compact">
      <thead><tr><th>Type</th><th>Domain</th><th>Publisher ID</th><th>Status</th><th>HTTP</th><th>Sample</th><th>URL</th></tr></thead>
      <tbody>
        <tr>
          <td>{{ result.kind }}</td>
          <td>{{ result.domain }}</td>
          <td>{{ result.publisher_id }}</td>
          <td class="{{ 'ok' if result.status=='Present' else 'err' }}">{{ result.status }}</td>
          <td>{{ result.status_code }}</td>
          <td class="small truncate">{{ result.sample or '' }}</td>
          <td class="small truncate">{{ result.url or '' }}</td>
        </tr>
      </tbody>
    </table>
  </div>

  <details class="box mt12">
    <summary>Extra checks</summary>
    <table class="compact">
      <thead><tr><th>Required line</th><th>Present?</th></tr></thead>
      <tbody>
        {% for label, val in result.required.items() %}
          <tr>
            <td class="small">{{ label }}</td>
            <td class="{{ 'ok' if val=='Yes' else ('muted' if val=='' else 'err') }}">{{ val or '—' }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </details>

  <div class="small mt8 muted">Explanation: {{ explanation }}</div>
  <div class='mt18'><a href='/'>← Run another check</a></div>
{% endblock %}"""

CRAWLER_HTML = """{% extends 'base.html' %}{% block content %}
  <h2 class="mt0">Bulk crawl</h2>

  <details class="help"><summary>Help</summary>
    <ul class="small muted">
      <li><b>in_app</b> → uses <i>Supply App Domain</i> → app-ads.txt</li>
      <li><b>mobile_web / web / site</b> → uses domain/URL → ads.txt</li>
      <li>Paste lines as: <code>domain,publisher_id[,type]</code></li>
    </ul>
  </details>

  <form method='POST' action='/crawl' enctype='multipart/form-data'>
    <label>Default type (if Inventory Type is missing)</label>
    <select name='default_kind'><option value='ads'>ads.txt</option><option value='app'>app-ads.txt</option></select>

    <label class="mt8">Paste rows</label>
    <textarea name='pairs_input' placeholder="example.com,pub-1234...,ads&#10;developer.com,pub-5678...,app"></textarea>

    <div class="or muted">— or —</div>
    <label>Upload CSV</label>
    <input type='file' name='csv_file' accept='.csv' />
    <div class="mt12"><button type='submit'>Run crawler</button></div>
  </form>
{% endblock %}"""

CRAWL_RESULTS_HTML = """{% extends 'base.html' %}{% block content %}
  <h2 class="mt0">Crawl results</h2>
  <div class="buttons">
    <form method='POST' action='/download_bulk_csv'>
      <input type='hidden' name='payload' value='{{ payload|tojson }}' />
      <button type='submit'>Download CSV</button>
    </form>
    {% if skipped|length %}
    <form method='POST' action='/download_skipped_csv'>
      <input type='hidden' name='payload' value='{{ payload|tojson }}' />
      <button type='submit'>Skipped CSV</button>
    </form>
    {% endif %}
  </div>
  <div class="small muted mt4">{{ results|length }} processed{% if skipped|length %}, {{ skipped|length }} skipped{% endif %}</div>

  <div class="table-scroll h300 mt8 stick-head">
    <table class="compact">
      <thead>
        <tr><th>#</th><th>Type</th><th>Domain</th><th>Publisher ID</th><th>Status</th><th>HTTP</th><th class="small">Sample</th><th class="small">URL</th></tr>
      </thead>
      <tbody>
      {% for r in results %}
        <tr>
          <td>{{ loop.index }}</td>
          <td>{{ r.kind }}</td>
          <td>{{ r.domain }}</td>
          <td>{{ r.publisher_id }}</td>
          <td class="{{ 'ok' if r.status=='Present' else 'err' }}">{{ r.status }}</td>
          <td>{{ r.status_code }}</td>
          <td class="small truncate">{{ r.sample or '' }}</td>
          <td class="small truncate">{{ r.url or '' }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <details class="box mt12">
    <summary>Extra checks (per file)</summary>
    <div class="table-scroll h240">
      <table class="compact">
        <thead>
          <tr><th>#</th><th>Domain</th>
            {% for label in headers_required %}<th class="small">{{ label }}</th>{% endfor %}
          </tr>
        </thead>
        <tbody>
          {% for r in results %}
            <tr>
              <td>{{ loop.index }}</td>
              <td>{{ r.domain }}</td>
              {% for label in headers_required %}
              <td class="{{ 'ok' if r.required.get(label)=='Yes' else ('muted' if r.required.get(label)=='' else 'err') }}">
                {{ r.required.get(label) or '—' }}
              </td>
              {% endfor %}
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </details>

  {% if skipped|length %}
  <details class="box mt12">
    <summary>Skipped rows ({{ skipped|length }})</summary>
    <div class="table-scroll h240">
      <table class="compact">
        <thead><tr><th>#</th><th>Publisher ID</th><th>Inventory Type</th><th>Supply App Domain</th><th>Domain/URL</th><th>Reason</th></tr></thead>
        <tbody>
          {% for s in skipped %}
            <tr>
              <td>{{ loop.index }}</td>
              <td class="small">{{ s.publisher_id }}</td>
              <td class="small">{{ s.inventory_type }}</td>
              <td class="small">{{ s.app_domain }}</td>
              <td class="small">{{ s.url_or_domain }}</td>
              <td class="err small">{{ s.reason }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </details>
  {% endif %}

  <div class='mt18'><a href='/crawler'>← Run another crawl</a></div>
{% endblock %}"""

app.jinja_loader = DictLoader({
    'base.html': BASE_HTML, 'index.html': INDEX_HTML, 'results.html': RESULTS_HTML,
    'crawler.html': CRAWLER_HTML, 'crawl_results.html': CRAWL_RESULTS_HTML
})

# ==========================
# Routes
# ==========================
@app.route("/", methods=["GET"])
def index():
    email, deny = require_iap_and_allowlist()
    if deny: return deny
    return render_template_string(INDEX_HTML, user_email=email, active="single", app_name=APP_NAME)

@app.route("/check", methods=["POST"])
def check():
    email, deny = require_iap_and_allowlist()
    if deny: return deny
    domain = request.form.get("domain","").strip()
    pub_id = request.form.get("publisher_id","").strip()
    kind = request.form.get("kind","ads")
    res = fetch_once(domain, pub_id, kind)
    explanation = explain_status(res["status"])
    class O(dict): __getattr__ = dict.get
    return render_template_string(RESULTS_HTML, user_email=email, active="single",
                                  result=O(res), explanation=explanation, app_name=APP_NAME)

@app.route("/crawler", methods=["GET"])
def crawler():
    email, deny = require_iap_and_allowlist()
    if deny: return deny
    return render_template_string(CRAWLER_HTML, user_email=email, active="crawler", app_name=APP_NAME)

@app.route("/crawl", methods=["POST"])
def crawl():
    email, deny = require_iap_and_allowlist()
    if deny: return deny

    default_kind = request.form.get("default_kind","ads")
    pairs = parse_pairs(request.form.get("pairs_input",""), default_kind)

    skipped = []
    f = request.files.get("csv_file")
    if f and f.filename:
        try:
            raw = f.read().decode("utf-8", errors="ignore")
            rdr = csv.DictReader(io.StringIO(raw))
            for raw_row in rdr:
                d, p, k, reason = row_to_triplet_auto(raw_row, default_kind)
                if reason:
                    row_lc = { (k.strip().lower() if isinstance(k,str) else k): v for k,v in raw_row.items() }
                    skipped.append({
                        "publisher_id": str(row_lc.get("publisher_id", row_lc.get("publisher & placement publisher id",""))),
                        "inventory_type": str(row_lc.get("inventory type", row_lc.get("publisher & placement inventory type",""))),
                        "app_domain": str(row_lc.get("supply app domain", row_lc.get("supply app supply app domain",""))),
                        "url_or_domain": str(row_lc.get("domain", row_lc.get("exchange measurements bundle id or page url",""))),
                        "reason": reason
                    })
                else:
                    pairs.append((d, p, k))
        except Exception:
            pass

    seen = set(); uniq = []
    for d, p, k in pairs:
        key = (d.lower(), p, normalize_kind(k))
        if key not in seen:
            seen.add(key); uniq.append((d, p, normalize_kind(k)))
    pairs = uniq[:MAX_ROWS]

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(fetch_once, d, p, k): (d, p, k) for d, p, k in pairs}
        for fut in as_completed(futs):
            r = fut.result()
            r["explain"] = explain_status(r["status"])
            results.append(r)

    results.sort(key=lambda x: (x["kind"], x["domain"], x["publisher_id"]))
    headers_required = [r["label"] for r in REQUIRED_LINES]
    payload = {"results": results, "headers_required": headers_required, "skipped": skipped}
    return render_template_string(CRAWL_RESULTS_HTML, user_email=email, active="crawler",
                                  results=results, headers_required=headers_required,
                                  skipped=skipped, payload=payload, app_name=APP_NAME)

@app.route("/download_bulk_csv", methods=["POST"])
def download_bulk_csv():
    email, deny = require_iap_and_allowlist()
    if deny: return deny
    payload = json.loads(request.form.get("payload","{}"))
    results = payload.get("results", [])
    headers_required = payload.get("headers_required", [r["label"] for r in REQUIRED_LINES])

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["type","domain","publisher_id","status","http","sample","url"] + headers_required)
    for r in results:
        row = [r.get("kind",""), r.get("domain",""), r.get("publisher_id",""),
               r.get("status",""), r.get("status_code",0),
               (r.get("sample") or "").replace("\n"," "), r.get("url","")]
        for label in headers_required:
            row.append(r["required"].get(label,""))
        w.writerow(row)
    mem = io.BytesIO(out.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="ads_app_ads_results.csv")

@app.route("/download_skipped_csv", methods=["POST"])
def download_skipped_csv():
    email, deny = require_iap_and_allowlist()
    if deny: return deny
    payload = json.loads(request.form.get("payload","{}"))
    skipped = payload.get("skipped", [])
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["publisher_id","inventory_type","supply_app_domain","domain_or_url","reason"])
    for s in skipped:
        w.writerow([s.get("publisher_id",""), s.get("inventory_type",""), s.get("app_domain",""), s.get("url_or_domain",""), s.get("reason","")])
    mem = io.BytesIO(out.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="skipped_rows.csv")

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type":"text/plain"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
