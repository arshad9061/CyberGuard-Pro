"""
CVE Lookup Module
Search and retrieve CVE vulnerability data from NVD API
"""

import requests
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")


class CVELookup:
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CVE_URL = "https://cve.circl.lu/api/cve/"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberGuard-Pro/1.0"})

    def lookup_cve(self, cve_id: str) -> dict:
        """Look up a specific CVE by ID"""
        try:
            resp = self.session.get(f"{self.CVE_URL}{cve_id}", timeout=15)
            data = resp.json()
            if not data:
                return {"error": f"CVE {cve_id} not found"}

            return {
                "id": data.get("id", cve_id),
                "summary": data.get("summary", "No summary available"),
                "published": data.get("Published", "N/A"),
                "modified": data.get("Modified", "N/A"),
                "cvss_score": data.get("cvss", "N/A"),
                "severity": self._get_severity(data.get("cvss", 0)),
                "references": data.get("references", [])[:5],
                "vulnerable_versions": data.get("vulnerable_configuration", [])[:5]
            }
        except Exception as e:
            return {"error": str(e), "cve_id": cve_id}

    def search_cves(self, keyword: str, results_per_page: int = 10) -> list:
        """Search CVEs by keyword"""
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page
            }
            resp = self.session.get(self.NVD_API_URL, params=params, timeout=20)
            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "N/A")
                metrics = cve.get("metrics", {})
                cvss_score = "N/A"
                severity = "N/A"
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "N/A")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", "N/A")

                cves.append({
                    "id": cve.get("id", "N/A"),
                    "description": desc[:200] + "..." if len(desc) > 200 else desc,
                    "published": cve.get("published", "N/A")[:10],
                    "cvss_score": cvss_score,
                    "severity": severity
                })
            return cves
        except Exception as e:
            return [{"error": str(e)}]

    def get_recent_cves(self, days: int = 7) -> list:
        """Get recently published CVEs"""
        try:
            from datetime import timedelta
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.000"),
                "resultsPerPage": 20
            }
            resp = self.session.get(self.NVD_API_URL, params=params, timeout=20)
            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "N/A")
                cves.append({
                    "id": cve.get("id", "N/A"),
                    "description": desc[:150] + "..." if len(desc) > 150 else desc,
                    "published": cve.get("published", "N/A")[:10]
                })
            return cves
        except Exception as e:
            return [{"error": str(e)}]

    def _get_severity(self, score) -> str:
        """Get severity label from CVSS score"""
        try:
            score = float(score)
            if score == 0: return "NONE"
            elif score < 4: return "LOW"
            elif score < 7: return "MEDIUM"
            elif score < 9: return "HIGH"
            else: return "CRITICAL"
        except Exception:
            return "UNKNOWN"
