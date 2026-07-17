import os
from dotenv import load_dotenv

load_dotenv()

def analyze_with_ai(finding):
    """Use AI to analyze XSS finding and give detailed report"""
    try:
        import google.generativeai as genai
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return rule_based_analysis(finding)
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = f"""
You are a professional web security expert. Analyze this XSS vulnerability:

URL: {finding['url']}
Type: {finding['type']}
Parameter: {finding['param']}
Payload: {finding['payload']}
Method: {finding['method']}

Provide:
1. Severity (Critical/High/Medium/Low)
2. Impact (what attacker can do)
3. Fix recommendation (specific code fix)
4. CVSS Score estimate

Keep response under 150 words. Be specific and technical.
"""
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception:
        return rule_based_analysis(finding)

def generate_smart_payloads(context):
    """Use AI to generate context-aware XSS payloads"""
    try:
        import google.generativeai as genai
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return []
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = f"""
You are an expert XSS penetration tester.
Generate 10 targeted XSS payloads for this context:

URL: {context.get('url')}
Input fields: {context.get('inputs')}
Page content hint: {context.get('hint', 'unknown')}

Rules:
- Return ONLY a JSON array of strings
- Make payloads specific to the context
- Include bypass techniques
- No explanation, just the JSON array

Example format: ["payload1", "payload2"]
"""
        response = model.generate_content(prompt)
        text  = response.text.strip()
        start = text.find("[")
        end   = text.rfind("]") + 1
        if start != -1 and end > start:
            import json
            return json.loads(text[start:end])
        return []
    except Exception:
        return []

def rule_based_analysis(finding):
    """Fallback analysis without AI"""
    analyses = {
        "Reflected XSS (Form)": "HIGH severity. Attacker can inject malicious scripts via form inputs. Can steal cookies, redirect users, or perform actions on behalf of victims. Fix: Use htmlspecialchars() or equivalent output encoding on all user inputs before rendering.",
        "Reflected XSS (URL Param)": "HIGH severity. XSS via URL parameter. Attacker can craft malicious URLs to trick users. Can lead to session hijacking and credential theft. Fix: Validate and encode all URL parameters. Implement Content-Security-Policy headers.",
        "Stored XSS": "CRITICAL severity. Persistent XSS stored in database. Affects ALL users who view the page. Can lead to mass account takeover. Fix: Sanitize input on storage AND encode on output. Use parameterized queries.",
        "DOM XSS": "HIGH severity. Client-side XSS via DOM manipulation. Bypasses server-side filters. Fix: Avoid innerHTML, use textContent. Sanitize data before passing to DOM sinks.",
        "Header XSS": "MEDIUM severity. XSS via HTTP headers reflected in response. Fix: Sanitize all reflected header values before including in HTML response."
    }
    xss_type = finding.get("type", "")
    for key, analysis in analyses.items():
        if key in xss_type:
            return analysis
    return "XSS vulnerability detected. Sanitize all user-controlled input before rendering in HTML. Implement Content-Security-Policy headers."
