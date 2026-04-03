"""
CyberGuard Pro — Unit Tests
"""

import unittest
import sys
sys.path.insert(0, '..')


class TestPasswordChecker(unittest.TestCase):
    def setUp(self):
        from core.password_checker import PasswordChecker
        self.checker = PasswordChecker()

    def test_weak_password(self):
        result = self.checker.check_strength("123456")
        self.assertLess(result["score"], 30)

    def test_strong_password(self):
        result = self.checker.check_strength("T3st!Secure@2024#X")
        self.assertGreater(result["score"], 70)

    def test_common_password_detected(self):
        result = self.checker.check_strength("password")
        self.assertFalse(result["checks"]["not_common"])

    def test_entropy_calculated(self):
        result = self.checker.check_strength("SecurePass123!")
        self.assertGreater(result["entropy"], 0)

    def test_suggestions_generated(self):
        result = self.checker.check_strength("abc")
        self.assertGreater(len(result["suggestions"]), 0)

    def test_generate_strong_password(self):
        pwd = self.checker.generate_strong_password(16)
        self.assertEqual(len(pwd), 16)
        result = self.checker.check_strength(pwd)
        self.assertGreaterEqual(result["score"], 80)


class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        from core.network_scanner import NetworkScanner
        self.scanner = NetworkScanner()

    def test_get_service_name(self):
        self.assertEqual(self.scanner._get_service_name(80), "http")
        self.assertEqual(self.scanner._get_service_name(443), "https")

    def test_scan_port_closed(self):
        result = self.scanner.scan_port("127.0.0.1", 19999, timeout=0.5)
        self.assertIn(result["state"], ["closed", "open"])


class TestWebScanner(unittest.TestCase):
    def setUp(self):
        from core.web_scanner import WebScanner
        self.scanner = WebScanner(timeout=5)

    def test_payloads_not_empty(self):
        self.assertGreater(len(self.scanner.SQLI_PAYLOADS), 0)
        self.assertGreater(len(self.scanner.XSS_PAYLOADS), 0)
        self.assertGreater(len(self.scanner.LFI_PAYLOADS), 0)


class TestCVELookup(unittest.TestCase):
    def setUp(self):
        from core.cve_lookup import CVELookup
        self.cve = CVELookup()

    def test_severity_mapping(self):
        self.assertEqual(self.cve._get_severity(9.5), "CRITICAL")
        self.assertEqual(self.cve._get_severity(7.0), "HIGH")
        self.assertEqual(self.cve._get_severity(4.0), "MEDIUM")
        self.assertEqual(self.cve._get_severity(2.0), "LOW")
        self.assertEqual(self.cve._get_severity(0), "NONE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
