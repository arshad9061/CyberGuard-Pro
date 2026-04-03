"""
Web Vulnerability Scanner Module
Detects common web vulnerabilities: SQLi, XSS, LFI, Open Redirect, etc.
"""

import requests
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")


class WebScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CyberGuard-Pro/1.0 (Security Scanner)"
        })
        self.vulnerabilities = []

    # ── SQLi Payloads ──────────────────────────────────────────────────────────
    SQLI_PAYLOADS = [
        "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
        "1' ORDER BY 1--", "1' UNION SELECT NULL--",
        "' AND SLEEP(3)--", "1; DROP TABLE users--"
    ]

    SQLI_ERRORS = [
        "sql syntax", "mysql_fetch", "ora-01756", "sqlite_error",
        "postgresql", "syntax error", "unclosed quotation",
        "you have an error in your sql", "warning: mysql"
    ]

    # ── XSS Payloads ──────────────────────────────────────────────────────────
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert('XSS')"
    ]

    # ── LFI Payloads ──────────────────────────────────────────────────────────
    LFI_PAYLOADS = [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../windows/win.ini",
        "....//....//....//etc/passwd",
        "%2F%2F%2F%2Fetc%2Fpasswd"
    ]

    LFI_SIGNATURES = ["root:x:0:0", "[fonts]", "daemon:", "bin/bash"]

    def get_all_links(self, url: str) -> list:
        """Extract all links from a webpage"""
        links = set()
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            pattern = r'href=["\']([^"\']+)["\']'
            found = re.findall(pattern, resp.text)
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for link in found:
                full = urljoin(base, link)
                if urlparse(full).netloc == urlparse(url).netloc:
                    links.add(full)
        except Exception:
            pass
        return list(links)

    def extract_forms(self, url: str) -> list:
        """Extract all forms from a page"""
        forms = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            form_pattern = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
            for form_html in form_pattern:
                form = {"action": "", "method": "get", "inputs": []}
                action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                if action_match:
                    form["action"] = urljoin(url, action_match.group(1))
                if method_match:
                    form["method"] = method_match.group(1).lower()
                inputs = re.findall(r'<input[^>]+>', form_html, re.IGNORECASE)
                for inp in inputs:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                    type_match = re.search(r'type=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                    if name_match:
                        form["inputs"].append({
                            "name": name_match.group(1),
                            "type": type_match.group(1) if type_match else "text"
                        })
                forms.append(form)
        except Exception:
            pass
        return forms

    def test_sqli(self, url: str) -> list:
        """Test URL parameters for SQL injection"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return vulns

        for param in params:
            for payload in self.SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    body = resp.text.lower()
                    for error in self.SQLI_ERRORS:
                        if error in body:
                            vuln = {
                                "type": "SQL Injection",
                                "severity": "CRITICAL",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": error
                            }
                            vulns.append(vuln)
                            self.vulnerabilities.append(vuln)
                            break
                except Exception:
                    pass
        return vulns

    def test_xss(self, url: str) -> list:
        """Test URL parameters for XSS"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return vulns

        for param in params:
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    if payload in resp.text:
                        vuln = {
                            "type": "Cross-Site Scripting (XSS)",
                            "severity": "HIGH",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": "Payload reflected in response"
                        }
                        vulns.append(vuln)
                        self.vulnerabilities.append(vuln)
                except Exception:
                    pass
        return vulns

    def test_lfi(self, url: str) -> list:
        """Test for Local File Inclusion"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return vulns

        for param in params:
            for payload in self.LFI_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    for sig in self.LFI_SIGNATURES:
                        if sig in resp.text:
                            vuln = {
                                "type": "Local File Inclusion (LFI)",
                                "severity": "CRITICAL",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Found signature: {sig}"
                            }
                            vulns.append(vuln)
                            self.vulnerabilities.append(vuln)
                            break
                except Exception:
                    pass
        return vulns

    def check_security_headers(self, url: str) -> dict:
        """Check for missing security headers"""
        important_headers = {
            "X-Frame-Options": "Prevents clickjacking",
            "X-XSS-Protection": "XSS filter",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Strict-Transport-Security": "HTTPS enforcement",
            "Content-Security-Policy": "Content security policy",
            "Referrer-Policy": "Referrer information control",
            "Permissions-Policy": "Browser feature control"
        }
        result = {"present": {}, "missing": {}}
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            for header, desc in important_headers.items():
                if header.lower() in [h.lower() for h in resp.headers]:
                    result["present"][header] = resp.headers.get(header, "")
                else:
                    result["missing"][header] = desc
        except Exception as e:
            result["error"] = str(e)
        return result

    def full_scan(self, url: str) -> dict:
        """Run all web vulnerability tests on a target"""
        print(f"\n  [*] Starting web scan on: {url}")
        report = {
            "target": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "security_headers": {},
            "links_found": 0
        }

        print("  [*] Checking security headers...")
        report["security_headers"] = self.check_security_headers(url)
        missing = len(report["security_headers"].get("missing", {}))
        print(f"  [!] Missing {missing} security header(s)")

        print("  [*] Extracting links...")
        links = self.get_all_links(url)
        report["links_found"] = len(links)
        print(f"  [+] Found {len(links)} links")

        all_urls = [url] + links
        for test_url in all_urls[:10]:  # Limit to 10 URLs
            print(f"  [*] Testing: {test_url[:60]}...")
            report["vulnerabilities"] += self.test_sqli(test_url)
            report["vulnerabilities"] += self.test_xss(test_url)
            report["vulnerabilities"] += self.test_lfi(test_url)

        print(f"  [+] Scan complete. Found {len(report['vulnerabilities'])} vulnerability/ies")
        return report
