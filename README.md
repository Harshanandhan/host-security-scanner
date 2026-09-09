# Host Security Scanner

Lab scanner for **hosts you are allowed to test**.

It does four things:

1. TCP connect scan on a port list
2. Banner / version grab (SSH, HTTP)
3. Cheap web GETs: SQL error strings, reflected XSS, security headers
4. TLS peek if 443 is open

It does **not** look up CVEs, run Nmap NSE, or exploit anything. There is **no CVE database** and no AI scoring layer.

Author: **Harsha Nandhan Reddy Gajulapalli**
Email: **harshanandhanreddy820@gmail.com**

![How this scanner works](images/architecture.png)

## Run

Authorized demo target: [scanme.nmap.org](http://scanme.nmap.org) (Nmap's public test host). Do not point this at random internet hosts.

```bash
pip install -r requirements.txt
python scanner.py -t scanme.nmap.org --quick --json results/scanme.json --report results/scanme.pdf
python render_images.py
```

## Evidence (this run)

Live re-run on **2026-09-09** (America/New_York) against `scanme.nmap.org` (`45.33.32.156`), **4.9 seconds**, `--quick` port list.

Command used:

```bash
python scanner.py -t scanme.nmap.org --quick --json results/scanme.json --report results/scanme.pdf
```

Console summary from that run:

```
Done in 4.9s  open_ports=4  web_checks=3
```

![Scan results](images/results-scanme.png)

**Open ports** (4)

| Port | Service | What we actually read |
|---:|---|---|
| 22 | ssh | `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` |
| 80 | http | `Apache/2.4.7 (Ubuntu)` HTTP 200 |
| 9929 | nping-echo | binary banner |
| 31337 | elite | open, no banner |

**Web checks** (`http://scanme.nmap.org`)

| Check | Result |
|---|---|
| SQL error on `GET ?id=` | no match |
| Reflected XSS on `GET ?q=` | payload not echoed |
| Security headers | **5 missing** (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) — LOW hygiene |

No TLS in this run: 443 was closed, so the SSL module was not used.

Artifacts from this run: `results/scanme.json`, `results/scanme.pdf`.

A missing header is not a CVE. An empty SQLi check is not "the site is safe." Numbers above are from the 2026-09-09 re-run, not invented CVE lookups.

## Layout

```
scanner.py             CLI
port_scanner.py        TCP connect + threads
service_detector.py    second banner read
web_scanner.py         GET heuristics
ssl_checker.py         TLS if 443 is open
report_generator.py    PDF from the same dict
results/               output of the scanme run
images/                diagrams built from that JSON
```

## License

MIT. Copyright (c) 2026 Harsha Nandhan Reddy Gajulapalli.
