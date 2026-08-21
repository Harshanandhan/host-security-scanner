"""Multi-threaded TCP connect scan."""

import socket
import threading
from queue import Queue

COMMON = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    8080: "http-alt",
    8443: "https-alt",
    9929: "nping-echo",
    31337: "elite",
}


def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


class PortScanner:
    def __init__(self, host: str, ports: str, timeout: float = 2.0, threads: int = 80):
        self.host = host
        self.timeout = timeout
        self.threads = threads
        self.ports = parse_ports(ports)
        self.open_ports: list[dict] = []
        self._lock = threading.Lock()
        self._queue: Queue = Queue()

    def _probe(self, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            if sock.connect_ex((self.host, port)) != 0:
                return
            banner = None
            try:
                sock.settimeout(1.5)
                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                data = sock.recv(256)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()[:120]
            except OSError:
                pass
            with self._lock:
                self.open_ports.append(
                    {
                        "port": port,
                        "state": "open",
                        "service": COMMON.get(port, "unknown"),
                        "banner": banner,
                    }
                )
        except OSError:
            pass
        finally:
            sock.close()

    def scan(self) -> list[dict]:
        for port in self.ports:
            self._queue.put(port)

        def worker() -> None:
            while True:
                port = self._queue.get()
                if port is None:
                    break
                self._probe(port)
                self._queue.task_done()

        workers = []
        n = min(self.threads, len(self.ports)) or 1
        for _ in range(n):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)
        self._queue.join()
        for _ in workers:
            self._queue.put(None)
        for t in workers:
            t.join()
        self.open_ports.sort(key=lambda p: p["port"])
        return self.open_ports
