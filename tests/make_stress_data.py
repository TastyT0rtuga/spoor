"""Fictional stress returns for the figure layout tests: long and Cyrillic account names, 260 shared IPs
(IPv4 and IPv6 documentation ranges), a large linked group, many failed-login bursts, a six-month
silence, and a one-day return that forces hour-level bins. Deterministic (fixed seed).

usage:  python tests/make_stress_data.py OUT_FOLDER   (writes OUT_FOLDER/long and OUT_FOLDER/short)"""
from __future__ import annotations

import csv
import datetime as dt
import random
import sys
from pathlib import Path

ACCOUNTS = [
    "a.very.long.account.name.used.only.to.test.figure.layout@subdomain.example-provider.co.uk",
    "Иван.Петров@пример.рф", "пользователь_тест", "Ж.Щукин-Юрьев", "jdoe.trader@example.com", "jd.alt@example.net",
    "snaps.user", "x", "renée.dupont@example.fr", "łukasz.żółć@example.pl",
] + [f"user{i:02d}@stress.example" for i in range(20)]


def ips() -> list[str]:
    out = [f"192.0.2.{i}" for i in range(1, 101)] + [f"198.51.100.{i}" for i in range(1, 101)] + [f"203.0.113.{i}" for i in range(1, 41)]
    out += [f"2001:db8:{i:x}:1:abcd:ef01:2345:{i:x}" for i in range(1, 21)]
    return out


def main(folder: str) -> None:
    out = Path(folder) / "long"
    out.mkdir(parents=True, exist_ok=True)
    short = Path(folder) / "short"
    short.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(42)
    pool = ips()
    rows = []
    t0 = dt.datetime(2023, 1, 2, 8, 0, tzinfo=dt.timezone.utc)
    usage = {a: rnd.sample(pool, 20) for a in ACCOUNTS}
    for a in ACCOUNTS:
        for k in range(rnd.randint(30, 120)):
            day = rnd.randint(0, 720)
            if 180 <= day < 365:            # a six-month silence
                day += 200
            t = t0 + dt.timedelta(days=day, minutes=rnd.randint(0, 1439))
            ev = rnd.choice(["Login", "Login", "Login", "Logout"])
            rows.append([t, a, ev, rnd.choice(usage[a]), "Success"])
    for n, a in enumerate(ACCOUNTS[:16]):    # failed-login bursts followed by a success from a new IP
        t = t0 + dt.timedelta(days=400 + 7 * n, hours=3)
        for j in range(6):
            rows.append([t + dt.timedelta(minutes=j), a, "Login", usage[a][0], "Failed"])
        rows.append([t + dt.timedelta(minutes=9), a, "Login", pool[-1 - n], "Success"])
        rows.append([t + dt.timedelta(minutes=12), a, "Password changed", pool[-1 - n], "Success"])
    rows.sort(key=lambda r: (r[0], r[1]))
    with open(out / "stress_logins.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Timestamp (UTC)", "Account", "Event", "IP Address", "Status"])
        for r in rows:
            w.writerow([r[0].strftime("%Y-%m-%d %H:%M:%S"), r[1], r[2], r[3], r[4]])
    # a second, short return: one day of activity for four accounts
    day = dt.datetime(2024, 3, 9, 22, 0, tzinfo=dt.timezone.utc)
    with open(short / "one_day.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Timestamp (UTC)", "Account", "Event", "IP Address", "Status"])
        for i in range(240):
            t = day + dt.timedelta(minutes=rnd.randint(0, 600))
            w.writerow([t.strftime("%Y-%m-%d %H:%M:%S"), rnd.choice(["shortday.a", "shortday.b", "Иван.Петров@пример.рф", "x"]),
                        "Login", rnd.choice(pool[:30]), "Success"])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "stress_returns")
