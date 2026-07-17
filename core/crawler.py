import requests
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

warnings.filterwarnings("ignore")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

def get_all_forms(url):
    try:
        res = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(res.content, "lxml")
        return soup.find_all("form")
    except Exception:
        return []

def get_form_details(form):
    details = {
        "action": form.attrs.get("action", ""),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    for tag in form.find_all(["input", "textarea", "select"]):
        details["inputs"].append({
            "type":  tag.attrs.get("type", "text"),
            "name":  tag.attrs.get("name", ""),
            "value": tag.attrs.get("value", "")
        })
    return details

def get_all_links(url, base_url):
    try:
        res = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(res.content, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            full = urljoin(base_url, a["href"])
            if urlparse(full).netloc == urlparse(base_url).netloc:
                links.add(full.split("#")[0])
        return links
    except Exception:
        return set()

def get_url_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] for k, v in params.items()}

def crawl(base_url, max_pages=20):
    visited  = set()
    to_visit = {base_url}
    pages    = []
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)
        try:
            forms  = get_all_forms(url)
            params = get_url_params(url)
            links  = get_all_links(url, base_url)
            to_visit.update(links - visited)
            pages.append({
                "url":    url,
                "forms":  [get_form_details(f) for f in forms],
                "params": params
            })
        except Exception:
            continue
    return pages
