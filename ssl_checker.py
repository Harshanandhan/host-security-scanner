"""TLS version, cipher, and certificate dates for port 443."""

import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone


class SSLChecker:
    def __init__(self, host: str, port: int = 443, timeout: float = 6.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def check(self) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                    version = tls.version()
                    cipher = tls.cipher()
                    der = tls.getpeercert(binary_form=True)
        except OSError as exc:
            return {"error": str(exc), "port": self.port}

        subject, issuer, not_after, not_before = {}, {}, "", ""
        if der:
            pem = ssl.DER_cert_to_PEM_cert(der)
            fd, path = tempfile.mkstemp(suffix=".pem")
            os.close(fd)
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(pem)
                decoded = ssl._ssl._test_decode_cert(path)
                subject = dict(x[0] for x in decoded.get("subject", []))
                issuer = dict(x[0] for x in decoded.get("issuer", []))
                not_after = decoded.get("notAfter", "")
                not_before = decoded.get("notBefore", "")
            except Exception:
                pass
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass

        issues = []
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            issues.append(f"old protocol {version}")
        if cipher and cipher[2] < 128:
            issues.append(f"weak key length {cipher[2]}")

        expired = False
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                expired = exp < datetime.now(timezone.utc)
                if expired:
                    issues.append("certificate expired")
            except ValueError:
                pass

        return {
            "port": self.port,
            "protocol": version,
            "cipher": cipher[0] if cipher else "",
            "bits": cipher[2] if cipher else None,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "expired": expired,
            "issues": issues,
        }
