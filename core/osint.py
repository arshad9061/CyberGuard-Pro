"""
OSINT (Open Source Intelligence) Module
Gather information about domains, IPs, and emails
"""

import socket
import requests
import json
import re
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")


class OSINTModule:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CyberGuard-Pro/1.0"
        })

    def get_ip_info(self, ip: str) -> dict:
        """Get geolocation and ASN info for an IP"""
        try:
            resp = self.session.get(f"https://ipapi.co/{ip}/json/", timeout=10)
            data = resp.json()
            return {
                "ip": ip,
                "city": data.get("city", "N/A"),
                "region": data.get("region", "N/A"),
                "country": data.get("country_name", "N/A"),
                "org": data.get("org", "N/A"),
                "asn": data.get("asn", "N/A"),
                "timezone": data.get("timezone", "N/A"),
                "latitude": data.get("latitude", "N/A"),
                "longitude": data.get("longitude", "N/A")
            }
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    def get_dns_records(self, domain: str) -> dict:
        """Get DNS records for a domain"""
        records = {}
        try:
            # A Record
            try:
                a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
                records["A"] = list(set([r[4][0] for r in a_records]))
            except Exception:
                records["A"] = []

            # AAAA Record
            try:
                aaaa_records = socket.getaddrinfo(domain, None, socket.AF_INET6)
                records["AAAA"] = list(set([r[4][0] for r in aaaa_records]))
            except Exception:
                records["AAAA"] = []

            # MX Record (via DNS over HTTPS)
            try:
                resp = self.session.get(
                    f"https://dns.google/resolve?name={domain}&type=MX",
                    timeout=10
                )
                data = resp.json()
                records["MX"] = [r["data"] for r in data.get("Answer", [])]
            except Exception:
                records["MX"] = []

            # TXT Record
            try:
                resp = self.session.get(
                    f"https://dns.google/resolve?name={domain}&type=TXT",
                    timeout=10
                )
                data = resp.json()
                records["TXT"] = [r["data"] for r in data.get("Answer", [])]
            except Exception:
                records["TXT"] = []

            # NS Record
            try:
                resp = self.session.get(
                    f"https://dns.google/resolve?name={domain}&type=NS",
                    timeout=10
                )
                data = resp.json()
                records["NS"] = [r["data"] for r in data.get("Answer", [])]
            except Exception:
                records["NS"] = []

        except Exception as e:
            records["error"] = str(e)

        return records

    def get_whois_info(self, domain: str) -> dict:
        """Get WHOIS information for a domain"""
        try:
            resp = self.session.get(
                f"https://api.whoisjson.com/v1/{domain}",
                timeout=10
            )
            data = resp.json()
            return {
                "domain": domain,
                "registrar": data.get("registrar", {}).get("name", "N/A"),
                "created": data.get("date_created", "N/A"),
                "expires": data.get("date_expires", "N/A"),
                "updated": data.get("date_updated", "N/A"),
                "status": data.get("status", []),
                "nameservers": data.get("nameservers", [])
            }
        except Exception:
            return {"domain": domain, "note": "WHOIS lookup requires network access"}

    def get_subdomains(self, domain: str) -> list:
        """Find subdomains using certificate transparency logs"""
        subdomains = set()
        try:
            resp = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15
            )
            data = resp.json()
            for cert in data:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub and sub != domain:
                        subdomains.add(sub)
        except Exception:
            pass
        return sorted(list(subdomains))

    def check_email_breach(self, email: str) -> dict:
        """Check if email appears in known breach databases"""
        result = {
            "email": email,
            "note": "For full breach checking, integrate HaveIBeenPwned API v3 with an API key.",
            "checked": False
        }
        # Validate email format
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            result["error"] = "Invalid email format"
        return result

    def get_server_info(self, url: str) -> dict:
        """Get web server information from HTTP headers"""
        try:
            resp = self.session.get(url, timeout=10, verify=False)
            return {
                "url": url,
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", "N/A"),
                "powered_by": resp.headers.get("X-Powered-By", "N/A"),
                "content_type": resp.headers.get("Content-Type", "N/A"),
                "technologies": self._detect_technologies(resp)
            }
        except Exception as e:
            return {"url": url, "error": str(e)}

    def _detect_technologies(self, response) -> list:
        """Detect web technologies from response"""
        tech = []
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text.lower()

        if "php" in headers.get("x-powered-by", "").lower():
            tech.append("PHP")
        if "asp.net" in headers.get("x-powered-by", "").lower():
            tech.append("ASP.NET")
        if "wordpress" in body or "wp-content" in body:
            tech.append("WordPress")
        if "joomla" in body:
            tech.append("Joomla")
        if "drupal" in body:
            tech.append("Drupal")
        if "react" in body or "__react" in body:
            tech.append("React")
        if "angular" in body:
            tech.append("Angular")
        if "vue" in body:
            tech.append("Vue.js")
        if "nginx" in headers.get("server", "").lower():
            tech.append("Nginx")
        if "apache" in headers.get("server", "").lower():
            tech.append("Apache")

        return tech

    def full_recon(self, target: str) -> dict:
        """Full OSINT reconnaissance on a domain"""
        print(f"\n  [*] Starting OSINT recon on: {target}")
        report = {
            "target": target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        print("  [*] Resolving IP address...")
        try:
            ip = socket.gethostbyname(target)
            report["ip"] = ip
            print(f"  [+] IP: {ip}")
            print("  [*] Getting IP geolocation...")
            report["ip_info"] = self.get_ip_info(ip)
        except Exception:
            report["ip"] = "Could not resolve"

        print("  [*] Getting DNS records...")
        report["dns_records"] = self.get_dns_records(target)

        print("  [*] Getting WHOIS info...")
        report["whois"] = self.get_whois_info(target)

        print("  [*] Finding subdomains...")
        report["subdomains"] = self.get_subdomains(target)
        print(f"  [+] Found {len(report['subdomains'])} subdomain(s)")

        print("  [*] Getting server info...")
        report["server_info"] = self.get_server_info(f"https://{target}")

        print("  [+] OSINT recon complete!")
        return report
