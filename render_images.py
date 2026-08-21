"""PNGs from results/scanme.json. Numbers come from the last scan."""

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
IMG = ROOT / "images"
FONT_DIR = Path(r"C:\Windows\Fonts")
NAVY = (15, 23, 42)
WHITE = (248, 250, 252)
MUTED = (148, 163, 184)
LINE = (30, 41, 59)
ACCENT = (56, 189, 248)
OK = (16, 185, 129)
FLAG = (234, 88, 12)


def font(name: str, size: int):
    for n in (name, "segoeui.ttf", "arial.ttf"):
        p = FONT_DIR / n
        if p.exists():
            return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()


def clean_banner(text: str | None) -> str:
    if not text:
        return "—"
    printable = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
    compact = " ".join(printable.split())
    if len(compact) < 8:
        return "(binary)"
    return compact[:70]


def architecture():
    w, h = 1400, 680
    im = Image.new("RGB", (w, h), NAVY)
    d = ImageDraw.Draw(im)
    title, body, small = font("segoeuib.ttf", 36), font("segoeui.ttf", 22), font("segoeui.ttf", 18)
    d.text((48, 36), "How this scanner works", font=title, fill=WHITE)
    d.text(
        (48, 88),
        "Harsha Nandhan Reddy Gajulapalli  ·  lab tool, authorized targets only",
        font=small,
        fill=MUTED,
    )
    boxes = [
        (50, 180, 300, 400, "1. Ports", "TCP connect scan\ncommon ports"),
        (360, 180, 610, 400, "2. Banners", "Read SSH/HTTP\nversion strings"),
        (670, 180, 920, 400, "3. Web GET", "SQLi errors, XSS\nreflection, headers"),
        (980, 180, 1340, 400, "4. Report", "JSON + PDF\nfrom this run"),
    ]
    for x1, y1, x2, y2, head, desc in boxes:
        d.rounded_rectangle((x1, y1, x2, y2), 18, fill=LINE)
        d.text((x1 + 24, y1 + 28), head, font=body, fill=ACCENT)
        d.multiline_text((x1 + 24, y1 + 90), desc, font=small, fill=WHITE, spacing=8)
    d.text((48, 460), "No NVD/CVE API. No exploit payloads. Missing headers are hygiene, not a 0-day.", font=small, fill=MUTED)
    d.text((48, 500), "Default demo target is scanme.nmap.org (explicitly offered by Nmap for testing).", font=small, fill=MUTED)
    d.text((48, 600), "harshanandhanreddy820@gmail.com", font=small, fill=MUTED)
    IMG.mkdir(exist_ok=True)
    im.save(IMG / "architecture.png")


def results_card(data: dict):
    w, h = 1400, 820
    im = Image.new("RGB", (w, h), NAVY)
    d = ImageDraw.Draw(im)
    title, body, small = font("segoeuib.ttf", 32), font("segoeui.ttf", 22), font("segoeui.ttf", 18)
    d.text((48, 28), "Results  ·  scanme.nmap.org", font=title, fill=WHITE)
    d.text(
        (48, 76),
        f"{data['scan_date']}  ·  {data['ip']}  ·  {data['duration_sec']}s  ·  {data['author']}",
        font=small,
        fill=MUTED,
    )
    d.rounded_rectangle((48, 130, 680, 780), 18, fill=LINE)
    d.text((72, 156), "Open TCP ports", font=body, fill=ACCENT)
    y = 210
    for p in data["ports"]:
        svc = next((s for s in data["services"] if s["port"] == p["port"]), {})
        label = svc.get("version") or p.get("service") or ""
        d.text((72, y), f"{p['port']}/tcp", font=body, fill=WHITE)
        d.text((200, y), f"{p['service']}  {label}", font=small, fill=MUTED)
        y += 44
        d.text((200, y - 8), clean_banner(p.get("banner")), font=small, fill=MUTED)
        y += 36

    d.rounded_rectangle((720, 130, 1352, 780), 18, fill=LINE)
    d.text((744, 156), "Web GET checks", font=body, fill=ACCENT)
    y = 220
    for f in data["web_findings"]:
        color = FLAG if f.get("vulnerable") else OK
        mark = "FLAG" if f.get("vulnerable") else "ok"
        d.rounded_rectangle((744, y, 820, y + 28), 8, fill=color)
        d.text((756, y + 4), mark, font=small, fill=WHITE)
        d.text((836, y + 2), f["test"].replace("_", " "), font=body, fill=WHITE)
        y += 40
        d.text((836, y), (f.get("note") or "")[:70], font=small, fill=MUTED)
        y += 50
        if f.get("missing"):
            d.text((836, y - 20), "missing: " + ", ".join(f["missing"][:3]) + ", …", font=small, fill=FLAG)
    d.text((744, 700), "SQL / XSS: no match on this host. Headers: 5 missing (LOW).", font=small, fill=MUTED)
    im.save(IMG / "results-scanme.png")


def main():
    data = json.loads((ROOT / "results" / "scanme.json").read_text(encoding="utf-8"))
    architecture()
    results_card(data)
    print("wrote", list(IMG.glob("*.png")))


if __name__ == "__main__":
    main()
