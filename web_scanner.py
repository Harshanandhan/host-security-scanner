"""Cheap GET checks: SQLi error strings, reflected XSS, missing headers.

These are lab heuristics. A miss does not mean the site is safe.
"""

import re
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

SQL_ERRORS = [
    r"SQL syntax",
    r"mysql_",
    r"PostgreSQL.*ERROR",
    r"ODBC SQL",
    r"SQLiteException",
]
SQL_PAYLOADS = ["'", "1' OR '1'='1", "' OR 1=1--"]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]
HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


class WebScanner:
    def __init__(self, base_url: str, timeout: float = 8.0):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "HostSecurityScanner/1.0"
        self.timeout = timeout

    def _get(self, url: str):
        return self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)

    def test_sql_injection(self) -> dict:
        evidence = []
        for payload in SQL_PAYLOADS:
            try:
                r = self._get(f"{self.base}/?id={payload}")
                for pat in SQL_ERRORS:
                    if re.search(pat, r.text, re.I):
                        evidence.append(f"payload={payload!r} matched {pat}")
                        return {
                            "test": "sql_injection_error",
                            "vulnerable": True,
                            "severity": "HIGH",
                            "evidence": evidence,
                            "note": "Error-based GET ?id= only. Not a full SQLi test.",
                        }
            except requests.RequestException:
                pass
        return {
            "test": "sql_injection_error",
            "vulnerable": False,
            "severity": "INFO",
            "evidence": [],
            "note": "No SQL error string on GET ?id=. Blind SQLi would not show here.",
        }

    def test_xss(self) -> dict:
        for payload in XSS_PAYLOADS:
            try:
                r = self._get(f"{self.base}/?q={payload}")
                if payload in r.text:
                    return {
                        "test": "reflected_xss",
                        "vulnerable": True,
                        "severity": "MEDIUM",
                        "evidence": [f"payload reflected: {payload}"],
                        "note": "GET ?q= reflection only.",
                    }
            except requests.RequestException:
                pass
        return {
            "test": "reflected_xss",
            "vulnerable": False,
            "severity": "INFO",
            "evidence": [],
            "note": "Payload not echoed on GET ?q=.",
        }

    def check_headers(self) -> dict:
        present = []
        missing = []
        try:
            r = self._get(self.base)
            for name in HEADERS:
                if name in r.headers:
                    present.append({"name": name, "value": r.headers[name][:80]})
                else:
                    missing.append(name)
            status = r.status_code
        except requests.RequestException as exc:
            return {
                "test": "security_headers",
                "vulnerable": False,
                "severity": "INFO",
                "error": str(exc),
                "present": [],
                "missing": HEADERS,
            }
        return {
            "test": "security_headers",
            "vulnerable": bool(missing),
            "severity": "LOW" if missing else "INFO",
            "status_code": status,
            "present": present,
            "missing": missing,
            "note": "Missing headers are hygiene, not a guaranteed exploit.",
        }
