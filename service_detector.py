"""Reconnect and read a short banner from an open TCP port."""

import re
import socket

PROBES = {
    21: b"",
    22: b"",
    25: b"EHLO scanner\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
    443: b"",
    8080: b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
}


class ServiceDetector:
    def __init__(self, host: str, timeout: float = 3.0):
        self.host = host
        self.timeout = timeout

    def detect(self, port: int) -> dict:
        info = {"port": port, "name": "unknown", "version": "", "banner": ""}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, port))
            probe = PROBES.get(port, b"")
            if probe:
                sock.sendall(probe)
            raw = sock.recv(1024)
            banner = raw.decode("utf-8", errors="replace").strip()
            info["banner"] = banner[:200]
            info.update(self._parse(banner, port))
        except OSError:
            pass
        finally:
            sock.close()
        return info

    @staticmethod
    def _parse(banner: str, port: int) -> dict:
        if "SSH-" in banner:
            m = re.search(r"SSH-[\d.]+-([^\s]+)", banner)
            return {"name": "ssh", "version": m.group(1) if m else ""}
        if banner.startswith("HTTP/") or "HTTP/" in banner[:20]:
            server = re.search(r"Server:\s*([^\r\n]+)", banner, re.I)
            return {
                "name": "http",
                "version": server.group(1).strip() if server else "",
            }
        if "ftp" in banner.lower() or banner[:3].isdigit():
            return {"name": "ftp" if port == 21 else "unknown", "version": banner.split("\n")[0][:60]}
        return {"name": "unknown", "version": ""}
