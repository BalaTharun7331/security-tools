import re, json, warnings
warnings.filterwarnings("ignore")

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

def extract_all_params(url, html=""):
    """
    Extract ALL parameters from:
    - URL query string
    - HTML forms (GET + POST)
    - JSON body params
    - Cookie params
    - Hidden inputs
    - Data attributes
    - JavaScript variables
    - Meta tags
    - API endpoints
    """
    params = {
        "url_params":    {},
        "form_params":   [],
        "cookie_params": [],
        "json_params":   [],
        "header_params": ["Referer", "User-Agent", "X-Forwarded-For", "X-Original-URL"],
        "js_params":     [],
        "api_endpoints": [],
        "hidden_inputs": [],
        "all_inputs":    []
    }

    # 1. URL query params
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    params["url_params"] = {k: v[0] for k, v in url_params.items()}

    if not html:
        try:
            r = requests.get(url, headers=HEADERS, timeout=15, verify=False)
            html = r.text
            # extract cookies
            for cookie in r.cookies:
                params["cookie_params"].append(cookie.name)
        except Exception:
            pass

    if not html:
        return params

    soup = BeautifulSoup(html, "html.parser")

    # 2. Form params
    for form in soup.find_all("form"):
        form_data = {
            "action": urljoin(url, form.attrs.get("action", url)),
            "method": form.attrs.get("method", "get").upper(),
            "inputs": []
        }
        for inp in form.find_all(["input", "textarea", "select"]):
            name  = inp.attrs.get("name", "")
            itype = inp.attrs.get("type", "text").lower()
            if name:
                form_data["inputs"].append({
                    "name":  name,
                    "type":  itype,
                    "value": inp.attrs.get("value", "")
                })
                if name not in params["all_inputs"]:
                    params["all_inputs"].append(name)
                if itype == "hidden":
                    params["hidden_inputs"].append(name)
        params["form_params"].append(form_data)

    # 3. JavaScript variable params
    js_param_pattern = re.compile(
        r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE
    )
    for script in soup.find_all("script"):
        text = script.string or ""
        for match in js_param_pattern.finditer(text):
            var_name = match.group(1)
            if var_name not in params["js_params"]:
                params["js_params"].append(var_name)

    # 4. API endpoints from JS
    api_pattern = re.compile(
        r'(?:fetch|axios|\.get|\.post|\.ajax)\s*\(\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    for script in soup.find_all("script"):
        text = script.string or ""
        for match in api_pattern.finditer(text):
            endpoint = match.group(1)
            if endpoint.startswith("/") or endpoint.startswith("http"):
                full = urljoin(url, endpoint)
                if full not in params["api_endpoints"]:
                    params["api_endpoints"].append(full)

    # 5. JSON params from script tags
    json_pattern = re.compile(r'\{[^{}]*"(\w+)"\s*:', re.IGNORECASE)
    for script in soup.find_all("script"):
        text = script.string or ""
        for match in json_pattern.finditer(text):
            key = match.group(1)
            if key not in params["json_params"] and len(key) > 1:
                params["json_params"].append(key)

    # 6. Data attributes
    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith("data-"):
                param_name = attr[5:]
                if param_name not in params["all_inputs"]:
                    params["all_inputs"].append(param_name)

    # 7. Input names from entire page
    for inp in soup.find_all(["input", "textarea", "select", "button"]):
        name = inp.attrs.get("name", "")
        if name and name not in params["all_inputs"]:
            params["all_inputs"].append(name)

    return params

def get_param_summary(params):
    """Return a clean summary of all found parameters"""
    summary = []
    if params["url_params"]:
        summary.append(f"URL Params ({len(params['url_params'])}): {list(params['url_params'].keys())}")
    if params["form_params"]:
        for f in params["form_params"]:
            inputs = [i["name"] for i in f["inputs"]]
            summary.append(f"Form {f['method']} {f['action']} -> {inputs}")
    if params["cookie_params"]:
        summary.append(f"Cookies ({len(params['cookie_params'])}): {params['cookie_params']}")
    if params["hidden_inputs"]:
        summary.append(f"Hidden Inputs: {params['hidden_inputs']}")
    if params["js_params"]:
        summary.append(f"JS Variables ({len(params['js_params'])}): {params['js_params'][:10]}")
    if params["api_endpoints"]:
        summary.append(f"API Endpoints ({len(params['api_endpoints'])}): {params['api_endpoints'][:5]}")
    return summary
