"""
Password Strength Checker & Analyzer Module
"""

import re
import hashlib
import math
import requests
from datetime import datetime


class PasswordChecker:
    # Common weak passwords list
    COMMON_PASSWORDS = [
        "password", "123456", "password123", "admin", "letmein",
        "qwerty", "monkey", "master", "dragon", "111111",
        "baseball", "iloveyou", "trustno1", "sunshine", "princess",
        "welcome", "shadow", "superman", "michael", "football",
        "charlie", "donald", "password1", "admin123", "root"
    ]

    def __init__(self):
        self.results = {}

    def check_strength(self, password: str) -> dict:
        """Comprehensive password strength analysis"""
        result = {
            "password": "*" * len(password),
            "length": len(password),
            "score": 0,
            "strength": "",
            "checks": {},
            "suggestions": [],
            "entropy": 0,
            "crack_time": ""
        }

        checks = {
            "length_8": len(password) >= 8,
            "length_12": len(password) >= 12,
            "length_16": len(password) >= 16,
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_digits": bool(re.search(r'\d', password)),
            "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            "no_spaces": " " not in password,
            "not_common": password.lower() not in self.COMMON_PASSWORDS,
            "no_repeated": not bool(re.search(r'(.)\1{2,}', password)),
            "no_sequential": not self._has_sequential(password)
        }

        result["checks"] = checks

        # Calculate score
        score = 0
        if checks["length_8"]: score += 10
        if checks["length_12"]: score += 10
        if checks["length_16"]: score += 10
        if checks["has_uppercase"]: score += 15
        if checks["has_lowercase"]: score += 15
        if checks["has_digits"]: score += 15
        if checks["has_special"]: score += 20
        if checks["not_common"]: score += 5

        result["score"] = min(score, 100)
        result["entropy"] = self._calculate_entropy(password)
        result["crack_time"] = self._estimate_crack_time(result["entropy"])

        # Determine strength label
        if score < 30:
            result["strength"] = "VERY WEAK 🔴"
        elif score < 50:
            result["strength"] = "WEAK 🟠"
        elif score < 70:
            result["strength"] = "MODERATE 🟡"
        elif score < 90:
            result["strength"] = "STRONG 🟢"
        else:
            result["strength"] = "VERY STRONG 💪"

        # Generate suggestions
        if not checks["length_12"]:
            result["suggestions"].append("Use at least 12 characters")
        if not checks["has_uppercase"]:
            result["suggestions"].append("Add uppercase letters (A-Z)")
        if not checks["has_lowercase"]:
            result["suggestions"].append("Add lowercase letters (a-z)")
        if not checks["has_digits"]:
            result["suggestions"].append("Add numbers (0-9)")
        if not checks["has_special"]:
            result["suggestions"].append("Add special characters (!@#$%^&*)")
        if not checks["not_common"]:
            result["suggestions"].append("This is a very common password — change it!")
        if not checks["no_repeated"]:
            result["suggestions"].append("Avoid repeated characters (e.g. aaa, 111)")
        if not checks["no_sequential"]:
            result["suggestions"].append("Avoid sequential patterns (e.g. abc, 123)")

        return result

    def check_pwned(self, password: str) -> dict:
        """Check if password was found in data breaches using HaveIBeenPwned API"""
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        result = {
            "checked": False,
            "pwned": False,
            "count": 0
        }
        try:
            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
                timeout=10
            )
            result["checked"] = True
            for line in resp.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    result["pwned"] = True
                    result["count"] = int(count)
                    break
        except Exception as e:
            result["error"] = str(e)
        return result

    def analyze_batch(self, passwords: list) -> list:
        """Analyze multiple passwords"""
        results = []
        for pwd in passwords:
            analysis = self.check_strength(pwd)
            pwned = self.check_pwned(pwd)
            analysis["pwned_info"] = pwned
            results.append(analysis)
        return results

    def generate_strong_password(self, length: int = 16) -> str:
        """Generate a cryptographically strong password"""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            check = self.check_strength(password)
            if check["score"] >= 80:
                return password

    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'\d', password): charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset_size += 32
        if charset_size == 0:
            return 0
        return round(len(password) * math.log2(charset_size), 2)

    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack based on entropy"""
        # Assuming 10 billion guesses per second (modern GPU)
        guesses_per_second = 10_000_000_000
        combinations = 2 ** entropy
        seconds = combinations / guesses_per_second

        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{int(seconds)} second(s)"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minute(s)"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hour(s)"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} day(s)"
        elif seconds < 31536000 * 100:
            return f"{int(seconds / 31536000)} year(s)"
        else:
            return "Centuries+"

    def _has_sequential(self, password: str) -> bool:
        """Check for sequential patterns"""
        sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl"]
        pwd_lower = password.lower()
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in pwd_lower:
                    return True
        return False
