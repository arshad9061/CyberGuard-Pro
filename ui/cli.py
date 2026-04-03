"""
CLI Interface Module
Beautiful command-line interface for CyberGuard Pro
"""

import os
import sys
import argparse


# ANSI Color Codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'


def c(text, color):
    return f"{color}{text}{Colors.RESET}"


BANNER = f"""
{Colors.RED}{Colors.BOLD}
  ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
{Colors.RESET}
{Colors.CYAN}                    ██████╗ ██████╗  ██████╗ 
                    ██╔══██╗██╔══██╗██╔═══██╗
                    ██████╔╝██████╔╝██║   ██║
                    ██╔═══╝ ██╔══██╗██║   ██║
                    ██║     ██║  ██║╚██████╔╝
                    ╚═╝     ╚═╝  ╚═╝ ╚═════╝{Colors.RESET}

{Colors.YELLOW}          [ All-in-One Cybersecurity Toolkit v1.0.0 ]{Colors.RESET}
{Colors.DIM}             For Ethical Hacking & Security Research{Colors.RESET}
{Colors.RED}             ⚠  Authorized Use Only  ⚠{Colors.RESET}
"""

MENU = f"""
{Colors.CYAN}{'─'*55}{Colors.RESET}
{Colors.BOLD}  MODULES{Colors.RESET}
{Colors.CYAN}{'─'*55}{Colors.RESET}

  {c('[1]', Colors.RED)} {c('Network Scanner', Colors.WHITE)}       — Scan hosts & open ports
  {c('[2]', Colors.RED)} {c('Web Vulnerability Scanner', Colors.WHITE)} — SQLi, XSS, LFI & more
  {c('[3]', Colors.RED)} {c('OSINT Reconnaissance', Colors.WHITE)}  — Domain & IP intelligence
  {c('[4]', Colors.RED)} {c('Password Analyzer', Colors.WHITE)}     — Strength check & breach
  {c('[5]', Colors.RED)} {c('CVE Lookup', Colors.WHITE)}            — Search known CVEs
  {c('[6]', Colors.RED)} {c('Generate Report', Colors.WHITE)}       — Export HTML/JSON report
  {c('[7]', Colors.RED)} {c('Full Auto Scan', Colors.WHITE)}        — Run all modules at once
  {c('[0]', Colors.DIM)} {c('Exit', Colors.DIM)}

{Colors.CYAN}{'─'*55}{Colors.RESET}
"""


class CLI:
    def __init__(self):
        self.scan_data = {}

    def clear(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def print_banner(self):
        print(BANNER)

    def print_menu(self):
        print(MENU)

    def get_input(self, prompt: str, color=Colors.GREEN) -> str:
        return input(f"\n{color}{Colors.BOLD}{prompt}{Colors.RESET} ").strip()

    def print_success(self, msg: str):
        print(f"\n  {c('✔', Colors.GREEN)} {msg}")

    def print_error(self, msg: str):
        print(f"\n  {c('✘', Colors.RED)} {msg}")

    def print_info(self, msg: str):
        print(f"\n  {c('►', Colors.CYAN)} {msg}")

    def print_warning(self, msg: str):
        print(f"\n  {c('⚠', Colors.YELLOW)} {msg}")

    def print_result_table(self, data: dict, title: str = ""):
        if title:
            print(f"\n  {c(title, Colors.BOLD)}")
            print(f"  {Colors.CYAN}{'─'*50}{Colors.RESET}")
        for key, value in data.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:5])
            print(f"  {c(key.title()+':', Colors.YELLOW):<35} {value}")

    def run_network_scanner(self):
        from core.network_scanner import NetworkScanner
        self.print_info("Network Scanner Module")
        target = self.get_input("Enter target IP or hostname:")
        if not target:
            self.print_error("No target specified")
            return

        choice = self.get_input("Quick scan (1-1024) or full scan (1-65535)? [1/2]:")
        port_range = (1, 65535) if choice == "2" else (1, 1024)

        scanner = NetworkScanner()
        results = scanner.full_scan(target)
        self.scan_data.update(results)

        print(f"\n  {c('═'*50, Colors.CYAN)}")
        print(f"  {c('SCAN RESULTS', Colors.BOLD)}")
        print(f"  {c('═'*50, Colors.CYAN)}")
        print(f"  Target   : {c(results['target'], Colors.WHITE)}")
        print(f"  Status   : {c('ALIVE' if results['alive'] else 'DOWN', Colors.GREEN if results['alive'] else Colors.RED)}")
        print(f"  Hostname : {results.get('hostname', 'N/A')}")
        print(f"\n  {c('Open Ports:', Colors.YELLOW)}")

        if results["open_ports"]:
            print(f"  {'Port':<8} {'Service':<15} {'Banner'}")
            print(f"  {'-'*50}")
            for p in results["open_ports"]:
                print(f"  {c(str(p['port']), Colors.RED):<8} {p['service']:<15} {p.get('banner', '')[:30]}")
        else:
            print(f"  {c('No open ports found', Colors.DIM)}")

    def run_web_scanner(self):
        from core.web_scanner import WebScanner
        self.print_info("Web Vulnerability Scanner")
        url = self.get_input("Enter target URL (e.g. https://example.com):")
        if not url:
            self.print_error("No URL specified")
            return
        if not url.startswith("http"):
            url = "https://" + url

        scanner = WebScanner()
        results = scanner.full_scan(url)
        self.scan_data.update(results)

        print(f"\n  {c('VULNERABILITIES FOUND:', Colors.BOLD)} {len(results['vulnerabilities'])}")
        for v in results["vulnerabilities"]:
            sev_color = Colors.RED if v["severity"] == "CRITICAL" else Colors.YELLOW
            print(f"\n  {c('['+ v['severity'] +']', sev_color)} {v['type']}")
            print(f"    Parameter : {v.get('parameter', 'N/A')}")
            print(f"    Evidence  : {v.get('evidence', 'N/A')}")

        missing = results.get("security_headers", {}).get("missing", {})
        if missing:
            print(f"\n  {c('MISSING SECURITY HEADERS:', Colors.YELLOW)} {len(missing)}")
            for h in missing:
                print(f"    {c('✘', Colors.RED)} {h}")

    def run_osint(self):
        from core.osint import OSINTModule
        self.print_info("OSINT Reconnaissance Module")
        domain = self.get_input("Enter domain (e.g. example.com):")
        if not domain:
            self.print_error("No domain specified")
            return

        osint = OSINTModule()
        results = osint.full_recon(domain)
        self.scan_data.update(results)

        print(f"\n  {c('IP INFO:', Colors.BOLD)}")
        ip_info = results.get("ip_info", {})
        for k, v in ip_info.items():
            if k not in ["ip", "error"]:
                print(f"    {c(k.title()+':', Colors.CYAN):<20} {v}")

        print(f"\n  {c('SUBDOMAINS:', Colors.BOLD)} {len(results.get('subdomains', []))}")
        for sub in results.get("subdomains", [])[:15]:
            print(f"    {c('►', Colors.GREEN)} {sub}")

    def run_password_checker(self):
        from core.password_checker import PasswordChecker
        import getpass
        self.print_info("Password Strength Analyzer")
        print(f"  {c('Options:', Colors.YELLOW)}")
        print(f"  [1] Check a password")
        print(f"  [2] Generate a strong password")

        choice = self.get_input("Select option:")
        checker = PasswordChecker()

        if choice == "1":
            password = getpass.getpass(f"\n  {c('Enter password (hidden):', Colors.GREEN)} ")
            result = checker.check_strength(password)

            print(f"\n  {c('ANALYSIS RESULTS:', Colors.BOLD)}")
            print(f"  Strength  : {result['strength']}")
            print(f"  Score     : {c(str(result['score'])+'/100', Colors.CYAN)}")
            print(f"  Entropy   : {result['entropy']} bits")
            print(f"  Crack Time: {c(result['crack_time'], Colors.YELLOW)}")

            pwned = checker.check_pwned(password)
            if pwned.get("checked"):
                if pwned["pwned"]:
                    print(f"  Breached  : {c('YES - Found in '+str(pwned['count'])+' breach(es)!', Colors.RED)}")
                else:
                    print(f"  Breached  : {c('Not found in known breaches ✔', Colors.GREEN)}")

            if result["suggestions"]:
                print(f"\n  {c('SUGGESTIONS:', Colors.YELLOW)}")
                for s in result["suggestions"]:
                    print(f"    {c('→', Colors.CYAN)} {s}")

        elif choice == "2":
            pwd = checker.generate_strong_password(16)
            print(f"\n  {c('Generated Password:', Colors.GREEN)}")
            print(f"  {c(pwd, Colors.BOLD)}")
            print(f"  {c('⚠ Save this immediately!', Colors.YELLOW)}")

    def run_cve_lookup(self):
        from core.cve_lookup import CVELookup
        self.print_info("CVE Lookup Module")
        print(f"  [1] Look up specific CVE")
        print(f"  [2] Search by keyword")
        print(f"  [3] Recent CVEs (last 7 days)")

        choice = self.get_input("Select option:")
        cve = CVELookup()

        if choice == "1":
            cve_id = self.get_input("Enter CVE ID (e.g. CVE-2021-44228):").upper()
            result = cve.lookup_cve(cve_id)
            if "error" not in result:
                print(f"\n  {c(result['id'], Colors.RED)} — {c(result['severity'], Colors.YELLOW)}")
                print(f"  CVSS Score : {result['cvss_score']}")
                print(f"  Published  : {result['published']}")
                print(f"\n  {c('Summary:', Colors.BOLD)}")
                print(f"  {result['summary'][:300]}...")
            else:
                self.print_error(result.get("error", "Not found"))

        elif choice == "2":
            keyword = self.get_input("Enter search keyword:")
            results = cve.search_cves(keyword)
            print(f"\n  {c('CVEs Found:', Colors.BOLD)} {len(results)}")
            for r in results[:10]:
                if "error" not in r:
                    print(f"\n  {c(r['id'], Colors.RED)} [{r.get('severity', 'N/A')}] Score: {r.get('cvss_score', 'N/A')}")
                    print(f"  {r['description'][:100]}...")

        elif choice == "3":
            results = cve.get_recent_cves(7)
            print(f"\n  {c('Recent CVEs:', Colors.BOLD)} {len(results)}")
            for r in results[:15]:
                if "error" not in r:
                    print(f"  {c(r['id'], Colors.RED)} [{r['published']}] {r['description'][:80]}...")

    def run_report_generator(self):
        from reports.report_generator import ReportGenerator
        if not self.scan_data:
            self.print_warning("No scan data available. Run a scan first!")
            return
        generator = ReportGenerator()
        html_file = generator.generate_html_report(self.scan_data)
        json_file = generator.generate_json_report(self.scan_data)
        self.print_success(f"HTML Report: {html_file}")
        self.print_success(f"JSON Report: {json_file}")

    def run_full_scan(self):
        self.print_info("Full Automatic Scan — All Modules")
        target = self.get_input("Enter target domain or IP:")
        if not target:
            self.print_error("No target specified")
            return

        self.print_warning("Starting full scan — this may take a few minutes...")

        from core.network_scanner import NetworkScanner
        from core.osint import OSINTModule
        from core.web_scanner import WebScanner
        from reports.report_generator import ReportGenerator

        print(f"\n  {c('[1/3] Network Scan', Colors.CYAN)}")
        scanner = NetworkScanner()
        net_results = scanner.full_scan(target)
        self.scan_data.update(net_results)

        print(f"\n  {c('[2/3] OSINT Recon', Colors.CYAN)}")
        osint = OSINTModule()
        osint_results = osint.full_recon(target)
        self.scan_data.update(osint_results)

        print(f"\n  {c('[3/3] Web Scan', Colors.CYAN)}")
        web = WebScanner()
        web_results = web.full_scan(f"https://{target}")
        self.scan_data.update(web_results)

        generator = ReportGenerator()
        html = generator.generate_html_report(self.scan_data, "full")
        self.print_success(f"Full scan complete! Report: {html}")

    def run(self):
        self.clear()
        self.print_banner()

        while True:
            self.print_menu()
            choice = self.get_input("Select module [0-7]:", Colors.RED)

            if choice == "0":
                print(f"\n  {c('Goodbye! Stay ethical. 👋', Colors.CYAN)}\n")
                sys.exit(0)
            elif choice == "1":
                self.run_network_scanner()
            elif choice == "2":
                self.run_web_scanner()
            elif choice == "3":
                self.run_osint()
            elif choice == "4":
                self.run_password_checker()
            elif choice == "5":
                self.run_cve_lookup()
            elif choice == "6":
                self.run_report_generator()
            elif choice == "7":
                self.run_full_scan()
            else:
                self.print_error("Invalid option")

            input(f"\n  {c('Press Enter to continue...', Colors.DIM)}")
