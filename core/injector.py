import requests
import json
import os
from urllib.parse import urljoin, urlencode, urlparse, parse_qs

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_payloads():
    path = os.path.join(BASE_DIR, "payloads", "payloads.json")
    with open(path) as f:
        data = json.load(f)
    all_payloads = []
    for category, payloads in data.items():
        for p in payloads:
            all_payloads.append({"payload": p, "category": category})
    return all_payloads

def inject_form(url, form_details, payload):
    target = urljoin(url, form_details["action"]) if form_details["action"] else url
    data   = {}
    for inp in form_details["inputs"]:
        if inp["type"] in ["submit", "button", "image", "reset"]:
            continue
        if inp["name"]:
            data[inp["name"]] = payload
    try:
        if form_details["method"] == "post":
            res = requests.post(target, data=data, headers=HEADERS, timeout=10, verify=False)
        else:
            res = requests.get(target, params=data, headers=HEADERS, timeout=10, verify=False)
        return res.text, target, data
    except Exception:
        return "", target, data

def inject_url_params(url, payload):
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)
    results = []
    for param in params:
        new_params = {k: v[0] for k, v in params.items()}
        new_params[param] = payload
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params)}"
        try:
            res = requests.get(new_url, headers=HEADERS, timeout=10, verify=False)
            results.append({"url": new_url, "param": param, "response": res.text})
        except Exception:
            continue
    return results
