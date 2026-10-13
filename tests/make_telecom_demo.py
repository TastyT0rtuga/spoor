"""Generate FICTIONAL telecom returns (call detail records and cell-site lists) for Spoor.

Every number is in the 555-01xx range reserved for fiction, IMSIs use the 001-01 test network,
IMEIs are random (with a valid Luhn digit) and carriers are invented. Coordinates are arbitrary
points in Northern Virginia; no real cell site is described.

Four targets across three carriers, each with its own layout:
  Northline Wireless  CSV, originating/terminating columns, times in UTC, separate cell-site list
  Bluepeak Mobile     CSV, direction + other party, Eastern local time named in the preamble,
                      separate cell-site list
  Corvane Telecom     XLSX, two targets on one sheet (MSISDN column), MOC/MTC call types,
                      MM/DD/YYYY dates, tower coordinates inline on every row

Planted patterns (checked by the tests) are listed in PLANTED at the bottom.

usage: python make_telecom_demo.py OUT_DIR
"""
from __future__ import annotations

import csv
import datetime as dt
import random
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

UTC = dt.timezone.utc
ET = ZoneInfo("America/New_York")
R = random.Random(20240420)

T1, T2, T3, T4 = "+17035550101", "+15715550102", "+12025550103", "+12405550104"
COMMON3 = "+17035550150"      # in contact with T1, T2 and T3
COMMON2 = "+15715550160"      # in contact with T2 and T4
START = dt.datetime(2024, 4, 1, tzinfo=UTC)
DAYS = 42


def luhn_digit(body: str) -> str:
    s = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return str((10 - s % 10) % 10)


def imei(tac: str) -> str:
    body = tac + "".join(R.choice("0123456789") for _ in range(14 - len(tac)))
    return body + luhn_digit(body)


IMEI_T1_A, IMEI_T1_B = imei("35391110"), imei("35391110")
IMEI_T2, IMEI_T2_B = imei("35672411"), imei("35672411")
IMEI_T3 = imei("86453103")
IMEI_T4_A = imei("35872209")
IMSI = {T1: "001010000000101", T2: "001010000000102", T3: "001010000000103", T4: "001010000000104"}
T1_IMEI_SWITCH = dt.datetime(2024, 4, 24, 3, 12, tzinfo=UTC)     # T1 changes handset
T4_TAKES_T2_IMEI = dt.datetime(2024, 5, 2, 18, 40, tzinfo=UTC)   # T2's handset appears on T4

# cell sites: (cell id, site name, lat, lon, azimuth, beamwidth)
NORTHLINE_SITES = [
    ("NL-1021-1", "Cedar Run N", 38.75210, -77.47390, 0, 65), ("NL-1021-2", "Cedar Run N", 38.75210, -77.47390, 120, 65),
    ("NL-1021-3", "Cedar Run N", 38.75210, -77.47390, 240, 65),
    ("NL-1047-1", "Bristow Ctr", 38.72290, -77.53610, 30, 65), ("NL-1047-2", "Bristow Ctr", 38.72290, -77.53610, 150, 65),
    ("NL-1088-1", "Old Town Mns", 38.75080, -77.47520, 90, 90),
    ("NL-1102-1", "Gainesville W", 38.79560, -77.61420, 10, 65), ("NL-1102-2", "Gainesville W", 38.79560, -77.61420, 200, 65),
    ("NL-1140-3", "Fairfax Sq", 38.84620, -77.30630, 270, 65),
]
BLUEPEAK_SITES = [
    ("40311", "BP Chantilly", 38.89420, -77.43110, 60, 60), ("40312", "BP Chantilly", 38.89420, -77.43110, 180, 60),
    ("40313", "BP Chantilly", 38.89420, -77.43110, 300, 60),
    ("40520", "BP Centreville", 38.84050, -77.42880, 45, 60), ("40521", "BP Centreville", 38.84050, -77.42880, 225, 60),
    ("40690", "BP Fair Lakes", 38.85320, -77.39040, 110, 60),
]
# Corvane: eNodeB-sector, coordinates written inline on every CDR row
CORVANE_SITES = [
    ("51210-1", 38.75228, -77.47371, 20), ("51210-2", 38.75228, -77.47371, 140),   # same tower as NL-1021 (~25 m)
    ("51330-1", 38.90460, -77.03630, 80), ("51330-2", 38.90460, -77.03630, 200),
    ("51402-3", 38.99070, -77.02610, 300), ("51477-1", 38.88330, -77.01710, 0),
]
COLOC_T1_T3 = dt.datetime(2024, 4, 20, 14, 3, 17, tzinfo=UTC)   # T1 on NL-1021-2, T3 on 51210-2 a few minutes apart
COLOC_T3_T4 = [dt.datetime(2024, 4, 9, 23, 41, tzinfo=UTC), dt.datetime(2024, 4, 27, 1, 15, tzinfo=UTC),
               dt.datetime(2024, 5, 6, 22, 5, tzinfo=UTC)]     # T3 and T4 on 51402-3


def fake_number() -> str:
    area = R.choice(["703", "571", "202", "240", "301", "540", "804", "410"])
    return f"+1{area}55501{R.randint(0, 99):02d}"


def pool(n, avoid) -> list[str]:
    out = []
    while len(out) < n:
        x = fake_number()
        if x not in avoid and x not in out and x not in (T1, T2, T3, T4, COMMON3, COMMON2):
            out.append(x)
    return out


def rand_time(day: int) -> dt.datetime:
    # mostly daytime/evening Eastern (12:00-04:00 UTC)
    h = R.choice(list(range(12, 24)) + [0, 1, 2, 3])
    return START + dt.timedelta(days=day, hours=h, minutes=R.randint(0, 59), seconds=R.randint(0, 59))


def gen_target(target, contacts, cells, n, extra_contacts):
    """Background records: (utc, other, direction, kind, seconds, cell)."""
    recs = []
    weights = [max(1, 12 - i) for i in range(len(contacts))]
    for _ in range(n):
        day = R.randrange(DAYS)
        other = R.choices(contacts, weights)[0]
        kind = R.choices(["voice", "sms", "data"], [5, 4, 1])[0]
        recs.append((rand_time(day), None if kind == "data" else other, R.choice(["out", "in"]), kind,
                     R.randint(5, 900) if kind == "voice" else (R.randint(60, 3600) if kind == "data" else 0),
                     R.choice(cells)))
    for when, other, direction, kind in extra_contacts:
        recs.append((when, other, direction, kind, R.randint(20, 400) if kind == "voice" else 0, R.choice(cells)))
    recs.sort(key=lambda r: r[0])
    return recs


def planted_contacts(target, number, k, start_day=3):
    out = []
    for i in range(k):
        when = START + dt.timedelta(days=start_day + i * 4, hours=15 + i % 6, minutes=7 * i % 60, seconds=11)
        out.append((when, number, "out" if i % 2 == 0 else "in", "voice" if i % 3 else "sms"))
    return out


def hms(s: int) -> str:
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def write_northline(out: Path):
    cells = [c[0] for c in NORTHLINE_SITES]
    extra = planted_contacts(T1, COMMON3, 6) + planted_contacts(T1, T2, 5, start_day=5)
    recs = gen_target(T1, pool(25, ()), cells, 260, extra)
    # the co-location moment on NL-1021-2
    recs.append((COLOC_T1_T3, pool(1, ())[0], "out", "voice", 95, "NL-1021-2"))
    recs.sort(key=lambda r: r[0])
    d = out / "Northline_Wireless"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "Northline_CDR_7035550101.csv", "w", newline="", encoding="utf-8") as f:
        f.write("Northline Wireless - Law Enforcement Relations\n")
        f.write("FICTIONAL DEMO RETURN - no real subscriber\n")
        f.write("Target Number: 7035550101\n\n")
        w = csv.writer(f)
        w.writerow(["Item", "Conn. Date/Time (UTC)", "Originating Number", "Terminating Number", "Elapsed Time",
                    "Call Type", "IMEI", "IMSI", "First Cell", "Last Cell"])
        for i, (t, other, direction, kind, secs, cell) in enumerate(recs, 1):
            me = "7035550101"
            o = (other or "")[2:]
            orig, term = (me, o) if direction == "out" else (o, me)
            if kind == "data":
                orig, term = me, ""
            dev = IMEI_T1_A if t < T1_IMEI_SWITCH else IMEI_T1_B
            ctype = {"voice": "Voice", "sms": "SMS", "data": "Data"}[kind]
            last = cell if R.random() < 0.8 else R.choice(cells)
            w.writerow([i, t.strftime("%m/%d/%Y %H:%M:%S"), orig, term, hms(secs), ctype, dev, IMSI[T1], cell, last])
    with open(d / "Northline_cell_sites.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Cell ID", "Site Name", "Latitude", "Longitude", "Azimuth", "Beamwidth"])
        for c in NORTHLINE_SITES:
            w.writerow(c)
    return recs


def write_bluepeak(out: Path):
    cells = [c[0] for c in BLUEPEAK_SITES]
    extra = planted_contacts(T2, COMMON3, 4, start_day=2) + planted_contacts(T2, COMMON2, 5, start_day=6)
    recs = gen_target(T2, pool(20, ()), cells, 220, extra)
    d = out / "Bluepeak_Mobile"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "Bluepeak_5715550102_usage.csv", "w", newline="", encoding="utf-8") as f:
        f.write("Bluepeak Mobile Subpoena Compliance\n")
        f.write("FICTIONAL DEMO RETURN - no real subscriber\n")
        f.write("Target: 5715550102\n")
        f.write("All times are Eastern\n\n")
        w = csv.writer(f)
        w.writerow(["Date", "Time", "Direction", "Other Party", "Type", "Duration (sec)", "Cell ID", "IMEI"])
        for t, other, direction, kind, secs, cell in recs:
            lt = t.astimezone(ET)
            w.writerow([lt.strftime("%Y-%m-%d"), lt.strftime("%H:%M:%S"),
                        "" if kind == "data" else ("Outgoing" if direction == "out" else "Incoming"),
                        (other or "").replace("+1", ""), {"voice": "Voice", "sms": "Text", "data": "Data"}[kind],
                        secs, cell, IMEI_T2 if t < T4_TAKES_T2_IMEI - dt.timedelta(hours=20) else IMEI_T2_B])
    with open(d / "Bluepeak_tower_list.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Sector ID", "Tower Name", "LAT", "LONG", "Azimuth", "Beam Width"])
        for c in BLUEPEAK_SITES:
            w.writerow(c)
    # the T1 -> T2 calls must also appear on T2's side (an independent return of the same calls)
    return recs


def write_corvane(out: Path, t1_recs):
    import openpyxl
    cells = [c[0] for c in CORVANE_SITES]
    coords = {c[0]: c[1:] for c in CORVANE_SITES}
    e3 = planted_contacts(T3, COMMON3, 5, start_day=4) + planted_contacts(T3, T4, 6, start_day=1)
    e4 = planted_contacts(T4, COMMON2, 4, start_day=8)
    r3 = gen_target(T3, pool(18, ()), ["51330-1", "51330-2"], 200, e3)
    r4 = gen_target(T4, pool(18, ()), ["51477-1"], 180, e4)
    r3.append((COLOC_T1_T3 + dt.timedelta(minutes=6, seconds=31), pool(1, ())[0], "in", "sms", 0, "51210-2"))
    for k, t in enumerate(COLOC_T3_T4):
        r3.append((t, pool(1, ())[0], "out", "voice", 60, "51402-3"))
        r4.append((t + dt.timedelta(minutes=3 + k), pool(1, ())[0], "in", "sms", 0, "51402-3"))
    rows = [(T3, r) for r in r3] + [(T4, r) for r in r4]
    rows.sort(key=lambda x: (x[1][0], x[0]))
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "CDR"
    ws.append(["Corvane Telecom - FICTIONAL DEMO RETURN - no real subscriber"])
    ws.append([])
    ws.append(["MSISDN", "Start Time (UTC)", "Call Type", "Other Number", "Duration", "eNodeB-Sector", "IMSI", "IMEI",
               "Latitude", "Longitude", "Azimuth"])
    types = {("voice", "out"): "MOC", ("voice", "in"): "MTC", ("sms", "out"): "SMS-MO", ("sms", "in"): "SMS-MT",
             ("data", "out"): "GPRS", ("data", "in"): "GPRS"}
    for msisdn, (t, other, direction, kind, secs, cell) in rows:
        dev = IMEI_T3 if msisdn == T3 else (IMEI_T2 if t >= T4_TAKES_T2_IMEI else IMEI_T4_A)
        lat, lon, az = coords[cell]
        ws.append([msisdn[2:], t.strftime("%m/%d/%Y %H:%M:%S"), types[(kind, direction)], (other or "")[2:], hms(secs),
                   cell, IMSI[msisdn], dev, lat, lon, az])
    d = out / "Corvane_Telecom"
    d.mkdir(parents=True, exist_ok=True)
    wb.save(d / "Corvane_CDR_2025550103_2405550104.xlsx")


def main(out_dir: str):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    t1 = write_northline(out)
    write_bluepeak(out)
    write_corvane(out, t1)
    (out / "README.txt").write_text(
        "FICTIONAL TELECOM DEMO DATA generated by tests/make_telecom_demo.py - no real people, numbers or cell sites.\n"
        "Numbers are in the 555-01xx fiction range; IMSIs use the 001-01 test network.\n", encoding="utf-8")


PLANTED = {
    "targets": [T1, T2, T3, T4],
    "common_contact_3": (COMMON3, {T1, T2, T3}),
    "common_contact_2": (COMMON2, {T2, T4}),
    "direct": [(T1, T2), (T3, T4)],
    "shared_imei": (IMEI_T2, {T2, T4}),
    "imei_change": (T1, IMEI_T1_A, IMEI_T1_B),
    "colocation": [(T1, T3), (T3, T4)],
}

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent.parent / "demo" / "telecom"))
