# modules/web_scanner.py
import requests
from bs4 import BeautifulSoup
import urllib.parse

# --- VULN DATABASE ---
# Payloads to test for vulnerabilities
SQLI_PAYLOADS = ["'", "' OR 1=1 --", '" OR 1=1 --']
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

def check_security_headers(url, headers):
    """
    Checks for missing security headers (Passive Scan).
    """
    findings = []
    
    # 1. Clickjacking Protection
    if 'X-Frame-Options' not in headers:
        findings.append(("🟠 Medium", "Missing X-Frame-Options", "Site is vulnerable to Clickjacking attacks."))
    
    # 2. XSS Protection Header
    if 'X-XSS-Protection' not in headers:
        findings.append(("🟢 Low", "Missing X-XSS-Protection", "Browser-based XSS filtering is disabled."))
        
    # 3. Content Security Policy (The Gold Standard)
    if 'Content-Security-Policy' not in headers:
        findings.append(("🟡 Medium", "Missing Content-Security-Policy (CSP)", "High risk of XSS and Data Injection."))
        
    # 4. HTTPS/HSTS
    if 'Strict-Transport-Security' not in headers and url.startswith("https"):
        findings.append(("🟢 Low", "Missing HSTS", "Connection is encrypted but not strictly enforced."))

    return findings

def check_sqli(url):
    """
    Tests URL parameters for SQL Injection vulnerability.
    """
    findings = []
    # Only test if parameters exist (e.g., ?id=1)
    if "=" not in url:
        return []

    for payload in SQLI_PAYLOADS:
        target = f"{url}{payload}"
        try:
            res = requests.get(target, timeout=5)
            # Check for database errors in HTML
            errors = ["SQL syntax", "mysql_fetch", "ORA-01756", "SQLite3::SQLException"]
            for err in errors:
                if err in res.text:
                    findings.append(("🔴 Critical", "SQL Injection Detected", f"Payload '{payload}' triggered a DB error."))
                    break
        except:
            pass
    return findings

def check_xss(url):
    """
    Tests inputs for Cross-Site Scripting.
    """
    findings = []
    if "=" not in url:
        return []
        
    for payload in XSS_PAYLOADS:
        # Simple reflection test
        target = f"{url}{payload}"
        try:
            res = requests.get(target, timeout=5)
            if payload in res.text:
                findings.append(("🔴 High", "Reflected XSS Detected", f"Payload '{payload}' was reflected in the response."))
                break
        except:
            pass
    return findings

def scan_website(url):
    """
    The Main Controller Function.
    """
    # 1. Normalize URL
    if not url.startswith("http"):
        url = "http://" + url
        
    results = []
    results.append(("🔵 Info", "Scan Target", f"Scanning: {url}"))
    
    try:
        # 2. Connection
        res = requests.get(url, timeout=10)
        results.append(("🟢 Info", "Server Status", f"Online ({res.status_code})"))
        
        # 3. Run Checks
        results.extend(check_security_headers(url, res.headers))
        results.extend(check_sqli(url))
        results.extend(check_xss(url))
        
    except requests.exceptions.RequestException as e:
        results.append(("🔴 Error", "Connection Failed", str(e)))
        
    return results