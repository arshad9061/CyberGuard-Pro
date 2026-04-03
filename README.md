# 🛡️ CyberGuard Pro

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge)

**All-in-One Cybersecurity Toolkit for Ethical Hackers & Security Professionals**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Contributing](#-contributing)

</div>

---

> ⚠️ **Legal Disclaimer**: CyberGuard Pro is intended for **authorized security testing only**. Only use this tool on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 **Network Scanner** | Discover live hosts, open ports & running services |
| 🌐 **Web Vulnerability Scanner** | Detect SQLi, XSS, LFI and more |
| 🕵️ **OSINT Recon** | Domain intel, DNS records, subdomains, IP geolocation |
| 🔑 **Password Analyzer** | Strength check, entropy analysis, breach detection |
| 🚨 **CVE Lookup** | Search NVD for known vulnerabilities |
| 📊 **Report Generator** | Export professional HTML & JSON reports |
| 🤖 **Full Auto Scan** | Run all modules with one command |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/arshad9061/CyberGuard-Pro.git
cd CyberGuard-Pro
python -m venv venv
source venv/bin/activate 
# Install dependencies
pip install -r requirements.txt

# Run CyberGuard Pro
python cyberguard.py
```

### Requirements
- Python 3.8+
- pip
- Internet connection (for OSINT & CVE modules)

---

## 🚀 Usage

### Interactive Mode (Recommended)
```bash
python cyberguard.py
```

### Command Line Examples

**Network Scan:**
```python
from core.network_scanner import NetworkScanner
scanner = NetworkScanner()
results = scanner.full_scan("192.168.1.1")
```

**Web Vulnerability Scan:**
```python
from core.web_scanner import WebScanner
scanner = WebScanner()
results = scanner.full_scan("https://target.com")
```

**Password Check:**
```python
from core.password_checker import PasswordChecker
checker = PasswordChecker()
result = checker.check_strength("MyP@ssw0rd!")
print(result["strength"])
```

**OSINT Recon:**
```python
from core.osint import OSINTModule
osint = OSINTModule()
results = osint.full_recon("example.com")
```

**CVE Lookup:**
```python
from core.cve_lookup import CVELookup
cve = CVELookup()
result = cve.lookup_cve("CVE-2021-44228")  # Log4Shell
```

---

## 🗂️ Project Structure

```
CyberGuard-Pro/
│
├── 📄 cyberguard.py          ← Main entry point
├── 📄 requirements.txt
├── 📄 README.md
│
├── 📁 core/
│   ├── network_scanner.py    ← Port scanner & host discovery
│   ├── web_scanner.py        ← SQLi, XSS, LFI scanner
│   ├── osint.py              ← OSINT & recon module
│   ├── password_checker.py   ← Password analysis
│   └── cve_lookup.py         ← CVE database lookup
│
├── 📁 reports/
│   └── report_generator.py   ← HTML & JSON report gen
│
├── 📁 ui/
│   └── cli.py                ← CLI interface & menus
│
└── 📁 tests/
    └── test_all.py           ← Unit tests
```

---

## 📸 Preview

```
  ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ...

  [1] Network Scanner       — Scan hosts & open ports
  [2] Web Vulnerability Scanner — SQLi, XSS, LFI & more
  [3] OSINT Reconnaissance  — Domain & IP intelligence
  [4] Password Analyzer     — Strength check & breach
  [5] CVE Lookup            — Search known CVEs
  [6] Generate Report       — Export HTML/JSON report
  [7] Full Auto Scan        — Run all modules at once
```

---

## 🔧 Configuration

Edit module parameters directly or set environment variables:

```bash
export CYBERGUARD_TIMEOUT=10        # Request timeout in seconds
export CYBERGUARD_THREADS=100       # Max concurrent threads
export CYBERGUARD_OUTPUT=./reports  # Report output directory
```

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

---

## 📋 Roadmap

- [ ] GUI Dashboard (Streamlit)
- [ ] Docker support
- [ ] Slack/Discord alerting
- [ ] Machine Learning threat classifier
- [ ] API integration (Shodan, VirusTotal)
- [ ] Scheduled scanning
- [ ] Database storage for scan history

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## ⭐ Support

If this project helped you, please give it a ⭐ on GitHub!

---

<div align="center">
Made with ❤️ for the cybersecurity community
</div>
