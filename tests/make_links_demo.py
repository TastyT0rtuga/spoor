"""FICTIONAL returns for the contact-path ("degrees of separation") tests: three call-record returns and a tower dump.

Planted structure (no real people or numbers; 555-02xx fiction range):
  T1 +17035550201 and T6 +15715550206 never contact each other and share no contact.
  T1 <-> X1 +15405550211 <-> T3 +12025550203 <-> X2 +13015550212 <-> T6      (4 hops; T3's own return carries the middle)
  T1 <-> X3 +18045550213 <-> T3                                             (second shortest T1-T3 route)
  611 is called by all three targets (a carrier short code: never used as a link)
  Tower dump (scene 2024-05-03): phone D1 +14105550221 calls X2 there; D2 +14105550222 calls T1's contact X1.
  Every other contact is unique to one target.
usage: python make_links_demo.py OUT_DIR"""
from __future__ import annotations

import datetime as dt
import random
import sys
from pathlib import Path

R = random.Random(20261014)
T1, T3, T6 = "7035550201", "2025550203", "5715550206"
X1, X2, X3 = "5405550211", "3015550212", "8045550213"
D1, D2 = "4105550221", "4105550222"
CELLS = ["NL-1021-1", "NL-1021-2", "NL-1088-1", "NL-1102-1", "NL-1140-3"]
SITES = """Cell ID,Site Name,Latitude,Longitude,Azimuth,Beamwidth
NL-1021-1,Cedar Run N,38.7521,-77.4739,0,65
NL-1021-2,Cedar Run N,38.7521,-77.4739,120,65
NL-1088-1,Elk Lick,38.6907,-77.5512,240,65
NL-1102-1,Calverton,38.6402,-77.6721,0,65
NL-1140-3,Bealeton S,38.5711,-77.7650,240,65
"""
_used = {T1, T3, T6, X1, X2, X3, D1, D2}


def filler() -> str:
    while True:
        n = f"{R.choice(['703', '571', '202', '301', '540', '804'])}55503{R.randint(0, 99):02d}"
        if n not in _used:
            _used.add(n)
            return n


def cdr(out: Path, target: str, links: list[tuple[str, int]]):
    """links: (other number, record count). Plus 611 and 6 one-off fillers."""
    rows = []
    t = dt.datetime(2024, 4, 1, 12, 0, 0)
    contacts = [(o, n) for o, n in links] + [("611", 2)] + [(filler(), 1) for _ in range(6)]
    for o, n in contacts:
        for _ in range(n):
            t += dt.timedelta(hours=R.randint(3, 30), minutes=R.randint(0, 59), seconds=R.randint(0, 59))
            mo = R.random() < 0.5
            kind = R.choice(["Voice", "SMS"])
            dur = "00:00:00" if kind == "SMS" else f"00:{R.randint(0, 14):02d}:{R.randint(0, 59):02d}"
            c = R.choice(CELLS)
            rows.append((t, target if mo else o, o if mo else target, dur, kind, c))
    rows.sort()
    L = ["Northline Wireless - Law Enforcement Relations", "FICTIONAL DEMO RETURN - no real subscriber", f"Target Number: {target}", "",
         "Item,Conn. Date/Time (UTC),Originating Number,Terminating Number,Elapsed Time,Call Type,IMEI,IMSI,First Cell,Last Cell"]
    imei = f"3539111{target[-7:]}"
    for i, (t, a, b, dur, kind, c) in enumerate(rows, 1):
        L.append(f"{i},{t:%m/%d/%Y %H:%M:%S},{a},{b},{dur},{kind},{imei},00101000{target[-7:]},{c},{c}")
    d = out / f"Return_{target}"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"Northline_CDR_{target}.csv").write_text("\n".join(L) + "\n", encoding="utf-8")
    (d / "Northline_cell_sites.csv").write_text(SITES, encoding="utf-8")


def dump(out: Path):
    s0 = dt.datetime(2024, 5, 3, 7, 0, 0)
    L = ["Search Criteria - USID:0000091", f"Date Range - From: {s0:%m/%d/%Y} 2:00 AM To: {s0:%m/%d/%Y} 3:00 AM Central",
         "Source,Conn Date,Conn Time (UTC),Disc Date,Disc Time (UTC),Originating Number,Dialed Number,Terminating Number,"
         "Call Type,Number Associated w/Tower,IMSI Associated w/Tower,IMEI Associated w/Tower,Minutes,Tower LAC/CID or ECGI,APN,MMS Type"]
    rows = [(D1, X2), (D2, X1)] + [(filler(), filler()) for _ in range(10)]
    for j, (num, o) in enumerate(rows):
        t = s0 + dt.timedelta(minutes=3 * j + 1)
        L.append(f"Voice,{t:%Y-%m-%d},{t:%H:%M:%S},{t:%Y-%m-%d},{t:%H:%M:%S},{num},{o},{o},MO,{num},0010100{num[-8:]},35{num}10,1.5,"
                 f"\"12355591:12355591\",,")
    L += ["", "Records show transactions processed through the dumped cells; FICTIONAL DEMO.", ""]
    d = out / "Tower_dump"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ReportTOWER_0000091.txt").write_text("\n".join(L) + "\n", encoding="utf-8")


def main(out_dir: str):
    out = Path(out_dir)
    cdr(out, T1, [(X1, 4), (X3, 2)])
    cdr(out, T3, [(X1, 3), (X2, 5), (X3, 2)])
    cdr(out, T6, [(X2, 3)])
    dump(out)


if __name__ == "__main__":
    main(sys.argv[1])
