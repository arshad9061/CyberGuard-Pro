#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║              CyberGuard Pro - v1.0.0                      ║
║         All-in-One Cybersecurity Toolkit                  ║
║              For Ethical Hackers Only                     ║
╚═══════════════════════════════════════════════════════════╝
"""

import sys
import argparse
from core.network_scanner import NetworkScanner
from core.web_scanner import WebScanner
from core.osint import OSINTModule
from core.password_checker import PasswordChecker
from core.cve_lookup import CVELookup
from reports.report_generator import ReportGenerator
from ui.cli import CLI

def main():
    cli = CLI()
    cli.run()

if __name__ == "__main__":
    main()
