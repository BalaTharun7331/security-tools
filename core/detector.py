import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.crawler import crawl
from core.injector import load_payloads, inject_form, inject_url_params
from core.ai_agent import generate_smart_payloads, analyze_vulnerability

def is_vulnerable(response_text, payload):
    return payload in response_text

def scan_page(page, socketio=None):
    findings = []
    url      = page["url"]

    def emit(msg, finding=None):
        if socketio:
            socketio.emit("scan_update", {"message": msg, "finding": finding})

    try:
        payloads = load_payloads()
    except Exception as e:
        emit(f"❌ Failed to load payloads: {e}")
        return findings

    emit(f"🔍 Scanning: {url}")

    # scan forms
    for form in page["forms"]:
        emit(f"📋 Testing {len(form['inputs'])} inputs in form at {url}")
        for p in payloads:
            try:
                response, target, data = inject_form(url, form, p["payload"])
                if response and is_vulnerable(response, p["payload"]):
                    finding = {
                        "url":      target,
                        "type":     f"Reflected XSS ({p['category']})",
                        "payload":  p["payload"],
                        "param":    str(list(data.keys())),
                        "severity": "HIGH",
                        "method":   "FORM"
                    }
                    finding["analysis"] = analyze_vulnerability(finding)
                    findings.append(finding)
                    emit(f"🚨 XSS Found! {target}", finding)
                    break
            except Exception as e:
                emit(f"⚠️ Form inject error: {e}")
                continue

    # ai smart payloads
    try:
        if page["forms"]:
            context = {
                "url":    url,
                "inputs": [f["inputs"] for f in page["forms"]],
                "params": page["params"]
            }
            smart = generate_smart_payloads(context)
            emit(f"🤖 AI generated {len(smart)} smart payloads")
            for payload in smart:
                for form in page["forms"]:
                    try:
                        response, target, data = inject_form(url, form, payload)
                        if response and is_vulnerable(response, payload):
                            finding = {
                                "url":      target,
                                "type":     "AI-Generated XSS",
                                "payload":  payload,
                                "param":    str(list(data.keys())),
                                "severity": "CRITICAL",
                                "method":   "AI_FORM"
                            }
                            finding["analysis"] = analyze_vulnerability(finding)
                            findings.append(finding)
                            emit(f"🤖🚨 AI XSS Found! {target}", finding)
                    except Exception:
                        continue
    except Exception as e:
        emit(f"⚠️ AI agent error (continuing scan): {e}")

    # scan url params
    if page["params"]:
        emit(f"🔗 Testing {len(page['params'])} URL params at {url}")
        for p in payloads:
            try:
                results = inject_url_params(url, p["payload"])
                for r in results:
                    if is_vulnerable(r["response"], p["payload"]):
                        finding = {
                            "url":      r["url"],
                            "type":     f"Reflected XSS URL ({p['category']})",
                            "payload":  p["payload"],
                            "param":    r["param"],
                            "severity": "HIGH",
                            "method":   "URL_PARAM"
                        }
                        finding["analysis"] = analyze_vulnerability(finding)
                        findings.append(finding)
                        emit(f"🚨 URL XSS Found! {r['url']}", finding)
            except Exception as e:
                emit(f"⚠️ URL param error: {e}")
                continue

    return findings

def full_scan(target_url, socketio=None):
    def emit(msg):
        if socketio:
            socketio.emit("scan_update", {"message": msg})

    try:
        emit(f"🕷️ Crawling {target_url}...")
        pages = crawl(target_url, max_pages=20)
        emit(f"✅ Found {len(pages)} pages to scan")
        if not pages:
            emit("❌ Could not reach target. Check URL and try again.")
            return []
        all_findings = []
        for i, page in enumerate(pages):
            emit(f"📄 Page {i+1}/{len(pages)}: {page['url']}")
            findings = scan_page(page, socketio)
            all_findings.extend(findings)
        emit(f"🏁 Scan complete! Found {len(all_findings)} vulnerabilities")
        return all_findings
    except Exception as e:
        emit(f"❌ Scan error: {e}")
        return []
