"""Generate a FICTIONAL set of subpoena returns for trying and testing Spoor.

All people, accounts and events are invented. Residential/mobile IPs use the IETF documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and CGNAT space; only
well-known hosting infrastructure uses real public ranges so the offline ASN lookup has
something to show. Planted patterns (for the tests) are listed in PLANTED at the bottom.

usage: python make_demo_data.py OUT_DIR [--big N]
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import random
import sys
import zipfile
from pathlib import Path

UTC = dt.timezone.utc
R = random.Random(20240414)

HOME_V4 = "203.0.113.5"
HOME_V6P = "2001:db8:4a1c:12:"
CGNAT = "100.70.12.34"
WORK = "198.51.100.20"
ATTACK = ["198.51.100.77", "198.51.100.78"]
VPS = "159.89.214.31"        # DigitalOcean (hosting)
VPN_NL = "185.107.56.10"     # NForce (hosting, NL)
BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
ETH = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
PHONE_FMT = "(703) 555-0142"
PHONE_E164 = "+17035550142"
G_ACCT = "jdoe.trader@example.com"
X_EMAIL = "jd.alt@example.net"
UA_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
UA_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
UA_LNX = "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"


def v6() -> str:
    return HOME_V6P + ":".join(f"{R.randrange(0, 65536):x}" for _ in range(4))


def google(out: Path, big: int = 0) -> None:
    d = out / "Google_LE_Return"
    d.mkdir(parents=True, exist_ok=True)
    rows = []
    day = dt.datetime(2024, 1, 1, tzinfo=UTC)
    end = dt.datetime(2024, 6, 30, tzinfo=UTC)
    while day <= end:
        if not (dt.datetime(2024, 2, 10, tzinfo=UTC) <= day < dt.datetime(2024, 3, 2, tzinfo=UTC)):
            for _ in range(R.randint(3, 9)):
                h = R.choice(list(range(13, 24)) + [0, 1, 2, 3])
                t = day + dt.timedelta(hours=h, minutes=R.randrange(60), seconds=R.randrange(60))
                if h <= 3:
                    t += dt.timedelta(days=1)
                p = R.random()
                if p < 0.6:
                    ip, ua = HOME_V4, UA_WIN
                elif p < 0.8:
                    ip, ua = v6(), UA_WIN
                elif p < 0.95:
                    ip, ua = CGNAT, UA_IOS
                else:
                    ip, ua = WORK, UA_WIN
                rows.append((t, ip, R.choice(["Login", "Login", "Login", "Logout"]), ua))
        day += dt.timedelta(days=1)
    burst0 = dt.datetime(2024, 4, 14, 9, 2, 0, tzinfo=UTC)
    for i in range(9):
        rows.append((burst0 + dt.timedelta(seconds=45 * i), ATTACK[i % 2], "Login failure - wrong password", UA_LNX))
    rows.append((dt.datetime(2024, 4, 14, 9, 15, 30, tzinfo=UTC), VPS, "Login", UA_LNX))
    rows.append((dt.datetime(2024, 4, 14, 9, 21, 10, tzinfo=UTC), VPS, "Password changed", UA_LNX))
    rows.append((dt.datetime(2024, 4, 14, 9, 22, 40, tzinfo=UTC), VPS, "2-Step Verification disabled", UA_LNX))
    rows.append((dt.datetime(2024, 4, 14, 9, 24, 0, tzinfo=UTC), VPS, "Recovery email changed", UA_LNX))
    for k in range(5):
        rows.append((dt.datetime(2024, 4, 15 + k, 3, 0, 0, tzinfo=UTC) + dt.timedelta(minutes=R.randrange(50)), VPS, "Login", UA_LNX))
    rows.append((dt.datetime(2024, 4, 16, 3, 6, 0, tzinfo=UTC), VPN_NL, "Login", UA_LNX))
    rows.append((dt.datetime(2024, 4, 16, 2, 58, 0, tzinfo=UTC), VPS, "Login", UA_LNX))
    for n in range(big):
        t = dt.datetime(2023, 1, 1, tzinfo=UTC) + dt.timedelta(seconds=R.randrange(365 * 86400))
        rows.append((t, R.choice([HOME_V4, CGNAT, WORK, v6()]), "Login", UA_WIN))
    rows.sort(key=lambda r: r[0])
    buf = io.StringIO()
    buf.write("Google LLC - Response to legal process (FICTIONAL DEMO DATA)\n")
    buf.write(f"Account: {G_ACCT}\n")
    buf.write("Note: All timestamps are in UTC.\n\n")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Timestamp", "IP Address", "Activity Type", "User Agent"])
    for t, ip, act, ua in rows:
        w.writerow([t.strftime("%Y-%m-%d %H:%M:%S UTC"), ip, act, ua])
    (d / f"{G_ACCT}.LoginActivity.csv").write_text(buf.getvalue(), encoding="utf-8")
    (d / f"{G_ACCT}.SubscriberInfo.txt").write_text(
        "GOOGLE SUBSCRIBER INFORMATION (FICTIONAL DEMO DATA)\n"
        f"Name: Jordan Doe\ne-Mail: {G_ACCT}\nRecovery e-Mail: {X_EMAIL}\nRecovery SMS: {PHONE_E164}\n"
        "Created on: 2018-11-02 16:40:11 UTC\nTerms of Service IP: 203.0.113.5, on 2018-11-02 16:40:11 UTC\n"
        "Services: Gmail, Google Drive, Google Pay\n", encoding="utf-8")


def exchange(out: Path) -> None:
    import openpyxl
    from zoneinfo import ZoneInfo
    pt = ZoneInfo("America/Los_Angeles")
    d = out / "Exchange_Return"
    d.mkdir(parents=True, exist_ok=True)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Logins"
    ws.append(["Example Exchange, Inc. - Records Production (FICTIONAL DEMO DATA)"])
    ws.append([f"Account: crypto_whale88 ({X_EMAIL})"])
    ws.append([])
    ws.append(["Created At (PT)", "IP Address", "Event", "Status", "Device", "User Email"])
    evs = []
    t = dt.datetime(2024, 1, 5, 18, 0)
    while t < dt.datetime(2024, 12, 20):
        ip = R.choice([HOME_V4, HOME_V4, CGNAT])
        evs.append((t, ip, "sign_in", "success", "Chrome on Windows" if ip == HOME_V4 else "iOS app"))
        t += dt.timedelta(hours=R.randint(20, 80), minutes=R.randrange(60))
    evs.append((dt.datetime(2024, 4, 14, 2, 20, 0), VPS, "sign_in", "success", "Firefox on Linux"))
    evs.append((dt.datetime(2024, 4, 14, 2, 31, 0), VPS, "withdrawal_address_added", "success", "Firefox on Linux"))
    evs.append((dt.datetime(2024, 4, 14, 2, 18, 30), VPS, "sign_in", "failed", "Firefox on Linux"))
    evs.append((dt.datetime(2024, 3, 10, 2, 30, 0), HOME_V4, "sign_in", "success", "Chrome on Windows"))   # skipped hour
    evs.append((dt.datetime(2024, 11, 3, 1, 30, 0), HOME_V4, "sign_in", "success", "Chrome on Windows"))   # repeated hour
    evs.sort(key=lambda e: e[0])
    for e in evs:
        ws.append([e[0], e[1], e[2], e[3], e[4], X_EMAIL])
    w2 = wb.create_sheet("Withdrawals")
    w2.append(["Date (PT)", "Asset", "Amount", "Destination Address", "Network"])
    w2.append([dt.datetime(2024, 4, 14, 3, 5, 0), "BTC", 1.25, BTC, "bitcoin"])
    w2.append([dt.datetime(2024, 4, 18, 11, 0, 0), "ETH", 14.0, ETH, "ethereum"])
    w2.append([dt.datetime(2024, 5, 2, 9, 30, 0), "BTC", 0.4, BTC, "bitcoin"])
    wb.save(d / "crypto_whale88_records.xlsx")
    _ = pt


def meta(out: Path) -> None:
    d = out / "Meta_Return"
    d.mkdir(parents=True, exist_ok=True)
    blocks = []
    times = [(dt.datetime(2024, 3, 15, 18, 0, 1, tzinfo=UTC), HOME_V4, "Login"),
             (dt.datetime(2024, 3, 20, 1, 12, 44, tzinfo=UTC), CGNAT, "Login"),
             (dt.datetime(2024, 4, 15, 3, 41, 9, tzinfo=UTC), VPS, "Login"),
             (dt.datetime(2024, 4, 15, 3, 55, 0, tzinfo=UTC), VPS, "Logout"),
             (dt.datetime(2024, 5, 1, 22, 3, 3, tzinfo=UTC), HOME_V4, "Login")]
    for t, ip, act in times:
        blocks.append(
            '<div class="t o"><div class="t i">Ip Address</div><div class="m"><div>' + ip + '</div></div></div>\n'
            '<div class="t o"><div class="t i">Time</div><div class="m"><div>' + t.strftime("%Y-%m-%d %H:%M:%S UTC") + '</div></div></div>\n'
            '<div class="t o"><div class="t i">Action</div><div class="m"><div>' + act + '</div></div></div>\n')
    msgs = [("Jordan Doe", "2024-04-14 10:02:00 UTC", f"send it to {BTC} today"),
            ("Ally Example", "2024-04-14 10:05:31 UTC", f"ok. call me {PHONE_FMT}"),
            ("Jordan Doe", "2024-04-16 02:00:12 UTC", "done")]
    rows = "".join(f"<tr><td>{a}</td><td>{s}</td><td>{b}</td></tr>\n" for a, s, b in msgs)
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Records - FICTIONAL DEMO DATA</title><style>.t{{margin:0}}</style></head>
<body>
<div class="div_table"><div class="t o"><div class="t i">Service</div><div class="m"><div>Facebook</div></div></div>
<div class="t o"><div class="t i">Target</div><div class="m"><div>100012345678</div></div></div>
<div class="t o"><div class="t i">Account Identifier</div><div class="m"><div>jordan.doe.5</div></div></div>
<div class="t o"><div class="t i">Registered Email Addresses</div><div class="m"><div>{X_EMAIL}</div></div></div>
<div class="t o"><div class="t i">Phone Numbers</div><div class="m"><div>+1 {PHONE_FMT}</div></div></div>
<div class="t o"><div class="t i">Registration Date</div><div class="m"><div>2019-06-01 14:22:10 UTC</div></div></div>
<div class="t o"><div class="t i">Registration Ip</div><div class="m"><div>{HOME_V4}</div></div></div>
</div>
<h2>Ip Addresses</h2>
<div class="div_table">
{''.join(blocks)}</div>
<h2>Messages</h2>
<table><tr><th>Author</th><th>Sent</th><th>Body</th></tr>
{rows}</table>
</body></html>
"""
    (d / "records.html").write_text(html, encoding="utf-8")


def isp_pdf(out: Path) -> None:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError:
        print("reportlab not installed - ISP PDF skipped")
        return
    d = out / "ISP_Return"
    d.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(d / "isp_subscriber_response.pdf"), pagesize=letter)
    y = 740
    for line in ["Example Cable Co. - Subscriber Information (FICTIONAL DEMO DATA)",
                 "Request: IP address 203.0.113.5 for 01/01/2024 through 06/30/2024 (all times Eastern)",
                 "Subscriber: Jordan Doe", "Service address: 123 Example Street, Fairfax, VA 22030",
                 f"Phone: {PHONE_FMT}", f"Email: {G_ACCT}", "",
                 "Lease history:",
                 "01/01/2024 00:00:00 EST   203.0.113.5   lease start   MAC 00:1A:2B:3C:4D:5E",
                 "03/10/2024 01:59:59 EST   203.0.113.5   lease renew   MAC 00:1A:2B:3C:4D:5E",
                 "06/30/2024 23:59:59 EDT   203.0.113.5   lease active  MAC 00:1A:2B:3C:4D:5E"]:
        c.drawString(54, y, line)
        y -= 18
    c.showPage()
    c.rect(100, 300, 400, 300, fill=1)   # a "scanned" page: no text
    c.showPage()
    c.save()


def bank(out: Path) -> None:
    d = out / "Bank_Return"
    d.mkdir(parents=True, exist_ok=True)
    lines = ["Date;Description;Amount;Currency;Counterparty",
             "02/01/2024;Payroll deposit;3.250,00;EUR;ACME GmbH",
             "25/03/2024;Zelle to José Müller " + PHONE_FMT + ";-450,00;EUR;José Müller",
             "14/04/2024;Wire to Example OTC Desk memo " + BTC + ";-38.000,00;EUR;Example OTC Desk",
             "05/04/2024;Card purchase;-12,40;EUR;Coffee Shop",
             "18/04/2024;Wire to Example OTC Desk;-15.500,00;EUR;Example OTC Desk",
             "30/04/2024;Transfer from Ally Example;1.200,00;EUR;Ally Example"]
    (d / "statement_transactions.csv").write_bytes(("\r\n".join(lines) + "\r\n").encode("cp1252"))


def snap_json(out: Path) -> None:
    d = out / "App_Return"
    d.mkdir(parents=True, exist_ok=True)
    hist = []
    base = dt.datetime(2024, 4, 1, tzinfo=UTC)
    for i in range(40):
        t = base + dt.timedelta(hours=7 * i + R.randrange(6), minutes=R.randrange(60))
        hist.append({"timestamp": int(t.timestamp() * 1000), "ip": R.choice([HOME_V4, CGNAT]), "event": "login_success", "device": "iPhone 14"})
    hist.append({"timestamp": int(dt.datetime(2024, 4, 14, 9, 40, 0, tzinfo=UTC).timestamp() * 1000), "ip": VPS,
                 "event": "login_success", "device": "Linux desktop"})
    hist.sort(key=lambda h: h["timestamp"])
    doc = {"subscriber": {"username": "jdoe_snaps", "email": G_ACCT, "phone": PHONE_E164,
                          "created": "2020-02-02T10:00:00Z", "note": "FICTIONAL DEMO DATA"},
           "login_history": hist}
    (d / "jdoe_snaps_account.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")


def dhcp(out: Path) -> None:
    d = out / "ISP_Return"
    d.mkdir(parents=True, exist_ok=True)
    lines = ["lease_start|lease_end|ip|mac|subscriber_id"]
    t = dt.datetime(2024, 1, 1, 5, 0, 0)
    for i in range(12):
        e = t + dt.timedelta(days=15)
        lines.append(f"{t:%Y-%m-%d %H:%M:%S}|{e:%Y-%m-%d %H:%M:%S}|{HOME_V4}|00:1a:2b:3c:4d:5e|CUST-778812")
        t = e
    (d / "dhcp_leases.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def russian(out: Path) -> None:
    d = out / "RU_Provider"
    d.mkdir(parents=True, exist_ok=True)
    rows = ["Дата (МСК);IP-адрес;Действие;Логин"]
    for t, ip, act in [(dt.datetime(2024, 4, 16, 6, 7), VPN_NL, "Неудачная попытка входа"),
                       (dt.datetime(2024, 4, 16, 6, 9), VPN_NL, "Вход в аккаунт"),
                       (dt.datetime(2024, 4, 16, 6, 30), VPN_NL, "Смена пароля"),
                       (dt.datetime(2024, 4, 16, 7, 2), VPN_NL, "Выход")]:
        rows.append(f"{t:%d.%m.%Y %H:%M};{ip};{act};jdoe_ru")
    (d / "vhod_log.csv").write_bytes(("\r\n".join(rows) + "\r\n").encode("cp1251"))


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "demo_returns")
    big = int(sys.argv[sys.argv.index("--big") + 1]) if "--big" in sys.argv else 0
    out.mkdir(parents=True, exist_ok=True)
    google(out, big)
    exchange(out)
    meta(out)
    isp_pdf(out)
    bank(out)
    snap_json(out)
    dhcp(out)
    russian(out)
    # deliver the Google return as a ZIP, as providers do
    g = out / "Google_LE_Return"
    with zipfile.ZipFile(out / "Google_LE_Return.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(g.iterdir()):
            z.write(p, f"Google_LE_Return/{p.name}")
    for p in sorted(g.iterdir()):
        p.unlink()
    g.rmdir()
    (out / "README.txt").write_text("FICTIONAL DEMO DATA generated by tests/make_demo_data.py - no real people or accounts.\n",
                                    encoding="utf-8")
    print(f"demo returns written to {out}")


PLANTED = {
    "failed_burst": ("jdoe.trader@example.com", 9, "2024-04-14 09:02:00"),
    "success_after_burst_ip": VPS,
    "change_from_new_ip": ("jdoe.trader@example.com", "Password changed", VPS),
    "shared_ip_accounts": (VPS, {"jdoe.trader@example.com", "jd.alt@example.net"}),
    "cross_source_btc": BTC,
    "shared_phone": PHONE_E164,
    "gap_days": ("jdoe.trader@example.com", 20),
    "nonexistent_local": "2024-03-10 02:30:00",
    "ambiguous_local": "2024-11-03 01:30:00",
    "assumed_tz_source": "dhcp_leases.txt",
    "dmy_source": "statement_transactions.csv",
    "empty_pdf_page": 2,
    "country_switch": (VPS, VPN_NL),
}

if __name__ == "__main__":
    main()
