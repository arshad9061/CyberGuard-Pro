"""
Network Scanner Module
Scans IPs, ports, and detects running services
"""

import socket
import subprocess
import concurrent.futures
import ipaddress
from datetime import datetime


class NetworkScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_results = {}

    def ping_host(self, host: str) -> bool:
        """Check if host is alive"""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except Exception:
            return False

    def scan_port(self, host: str, port: int, timeout: float = 1.0) -> dict:
        """Scan a single port"""
        result = {
            "port": port,
            "state": "closed",
            "service": self._get_service_name(port),
            "banner": ""
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            connection = sock.connect_ex((host, port))
            if connection == 0:
                result["state"] = "open"
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    result["banner"] = banner[:100] if banner else ""
                except Exception:
                    pass
            sock.close()
        except socket.error:
            pass
        return result

    def scan_ports(self, host: str, port_range: tuple = (1, 1024), threads: int = 100) -> list:
        """Scan multiple ports concurrently"""
        print(f"  [*] Scanning {host} ports {port_range[0]}-{port_range[1]}...")
        open_ports = []
        ports = range(port_range[0], port_range[1] + 1)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result["state"] == "open":
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        self.open_ports = open_ports
        return open_ports

    def scan_network(self, network: str) -> list:
        """Scan all hosts in a network range"""
        print(f"  [*] Scanning network {network}...")
        live_hosts = []
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.ping_host, str(host)): str(host) for host in hosts}
                for future in concurrent.futures.as_completed(futures):
                    host_ip = futures[future]
                    if future.result():
                        hostname = self._resolve_hostname(host_ip)
                        live_hosts.append({
                            "ip": host_ip,
                            "hostname": hostname,
                            "status": "up"
                        })
                        print(f"  [+] Host UP: {host_ip} ({hostname})")
        except ValueError as e:
            print(f"  [!] Invalid network: {e}")
        return live_hosts

    def full_scan(self, host: str) -> dict:
        """Full scan: ping + port scan + service detection"""
        print(f"\n  [*] Starting full scan on {host}")
        report = {
            "target": host,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alive": False,
            "hostname": "",
            "open_ports": []
        }

        if self.ping_host(host):
            report["alive"] = True
            report["hostname"] = self._resolve_hostname(host)
            print(f"  [+] Host is ALIVE")
            open_ports = self.scan_ports(host, (1, 1024))
            report["open_ports"] = open_ports
            print(f"  [+] Found {len(open_ports)} open port(s)")
        else:
            print(f"  [-] Host appears to be DOWN or blocking ICMP")

        self.scan_results = report
        return report

    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch"
        }
        try:
            return socket.getservbyport(port)
        except Exception:
            return common_ports.get(port, "unknown")

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "unknown"
