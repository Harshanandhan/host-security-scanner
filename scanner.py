#!/usr/bin/env python3
"""
Host security scanner (lab)
Author: Harsha Nandhan Reddy Gajulapalli
Email: harshanandhanreddy820@gmail.com

TCP connect scan, banner grab, a few web GET checks, TLS peek.
Authorized targets only. Not a pentest. No CVE database.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from port_scanner import PortScanner
from report_generator import ReportGenerator
from service_detector import ServiceDetector
from ssl_checker import SSLChecker
from web_scanner import WebScanner

AUTHOR = "Harsha Nandhan Reddy Gajulapalli"
EMAIL = "harshanandhanreddy820@gmail.com"
HERE = Path(__file__).resolve().parent

QUICK_PORTS = (
    "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5900,8080,8443,9929,31337"
)


def strip_host(target: str) -> tuple[str, str | None]:
    """Return (hostname, http_base_or_None)."""
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname or target, f"{parsed.scheme}://{parsed.netloc}"
    return target.split("/")[0], None


def resolve(host: str) -> str:
    return socket.gethostbyname(host)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lab host scanner. Use only on systems you are allowed to test."
    )
    parser.add_argument("-t", "--target", required=True, help="hostname, IP, or URL")
    parser.add_argument("-p", "--ports", default="1-1024", help="e.g. 22,80,443 or 1-1024")
    parser.add_argument("--quick", action="store_true", help="small common-port list")
    parser.add_argument("--web-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--threads", type=int, default=80)
    parser.add_argument("--json", help="write JSON results")
    parser.add_argument("--report", help="write PDF report")
    args = parser.parse_args()

    host, url_base = strip_host(args.target)
    try:
        ip = resolve(host)
    except socket.gaierror:
        print(f"Cannot resolve {host}")
        sys.exit(2)

    ports = QUICK_PORTS if args.quick else args.ports
    started = datetime.now()
    results = {
        "target": args.target,
        "host": host,
        "ip": ip,
        "scan_date": started.strftime("%Y-%m-%d %H:%M:%S"),
        "author": AUTHOR,
        "email": EMAIL,
        "ports": [],
        "services": [],
        "web_findings": [],
        "ssl": None,
        "note": "Authorized lab use only. Connect-scan + GET heuristics. No CVE lookup.",
    }

    print(f"Host security scanner")
    print(f"{AUTHOR}")
    print(f"Target {host} ({ip})")
    print()

    if not args.web_only:
        print(f"TCP scan ports={ports} timeout={args.timeout}s")
        opened = PortScanner(host, ports, timeout=args.timeout, threads=args.threads).scan()
        results["ports"] = opened
        if not opened:
            print("No open ports in this set.")
        for item in opened:
            raw = (item.get("banner") or "")[:50]
            # Windows consoles (cp1252) choke on binary banners; keep ASCII-safe preview.
            preview = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in raw)
            print(f"  {item['port']:>5}/tcp  {item['service']:12}  {preview}")

        svc = ServiceDetector(host)
        for item in opened:
            detected = svc.detect(item["port"])
            results["services"].append(detected)
            extra = detected.get("version") or detected.get("name")
            if extra and extra != "unknown":
                print(f"           banner-parse: {detected.get('name')} {detected.get('version')}")

        if any(p["port"] in (443, 8443) for p in opened):
            tls_port = 443 if any(p["port"] == 443 for p in opened) else 8443
            print(f"TLS on {tls_port}")
            results["ssl"] = SSLChecker(host, tls_port).check()
            ssl = results["ssl"]
            if ssl.get("error"):
                print(f"  TLS error: {ssl['error']}")
            else:
                print(f"  {ssl.get('protocol')}  {ssl.get('cipher')}  exp {ssl.get('not_after')}")
                for issue in ssl.get("issues") or []:
                    print(f"  issue: {issue}")

    web_ports = [p["port"] for p in results["ports"] if p["port"] in (80, 443, 8080, 8443)]
    if url_base or web_ports or args.web_only:
        if url_base:
            base = url_base
        elif 443 in web_ports:
            base = f"https://{host}"
        else:
            base = f"http://{host}"
        print(f"Web checks {base}")
        web = WebScanner(base)
        for finding in (web.test_sql_injection(), web.test_xss(), web.check_headers()):
            results["web_findings"].append(finding)
            flag = "FLAG" if finding.get("vulnerable") else "ok"
            print(f"  [{flag}] {finding.get('test')}: {finding.get('note') or finding.get('error','')}")
            if finding.get("missing"):
                print(f"         missing headers: {', '.join(finding['missing'])}")

    results["duration_sec"] = round((datetime.now() - started).total_seconds(), 2)
    print()
    print(
        f"Done in {results['duration_sec']}s  "
        f"open_ports={len(results['ports'])}  web_checks={len(results['web_findings'])}"
    )

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote {args.json}")
    if args.report:
        ReportGenerator(results).generate_pdf(args.report)
        print(f"Wrote {args.report}")


if __name__ == "__main__":
    main()
