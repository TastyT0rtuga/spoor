"""KML export of telecom records for Google Earth Pro / ArcGIS / QGIS (opens offline).

report/exports/telecom.kml:
  Cell sites            the sites the records used (not whole tower lists): a point per site and a wedge per
                        sector (azimuth +/- beamwidth/2). The wedge length is a fixed drawing aid
                        (kml_sector_km), NOT a coverage estimate.
  <target>              one folder per target: every located call/text/data record, time-stamped (use the time
                        slider), with the record's citation and the citation of its tower-list row.
  Location estimates    timing-advance and ping positions: the carrier's estimate of where the DEVICE was,
                        with its confidence - kept apart from cell sites.
  Tower dumps           one folder per dump source/section: records of every phone on the dumped towers.
  Co-location           one point per co-location occasion with both citations (from the analysis).
No external references: no icon URLs, no network links, no scripts. Deterministic output."""
from __future__ import annotations

import json
import math
from xml.sax.saxutils import escape

from . import db as dbm

# KML colours are aabbggrr. Distinct, colour-blind-safer hues (Okabe-Ito order).
PALETTE = ["ff0072b2", "ff00a5e6", "ff73b409", "ff4294f0", "ffa779cc", "ff009ed5", "ffe9b456", "ff000000"]
KIND_WORD = {"voice": "Call", "sms": "Text", "mms": "MMS", "rcs": "Chat (RCS)", "data": "Data"}


def _kml_time(ts: str | None) -> str | None:
    if not ts or len(ts) < 19:
        return None
    return ts[:10] + "T" + ts[11:19] + "Z"


def _wedge(lat, lon, az, bw, length_km, steps=8):
    pts = [(lon, lat)]
    half = (bw or 60) / 2
    for k in range(steps + 1):
        b = math.radians((az - half) + (2 * half) * k / steps)
        d = length_km / 6371.0088
        la1, lo1 = math.radians(lat), math.radians(lon)
        la2 = math.asin(math.sin(la1) * math.cos(d) + math.cos(la1) * math.sin(d) * math.cos(b))
        lo2 = lo1 + math.atan2(math.sin(b) * math.sin(d) * math.cos(la1), math.cos(d) - math.sin(la1) * math.sin(la2))
        pts.append((math.degrees(lo2), math.degrees(la2)))
    pts.append((lon, lat))
    return " ".join(f"{x:.6f},{y:.6f},0" for x, y in pts)


def _e(s) -> str:
    return escape("" if s is None else str(s))


def _cite(con, eid):
    if not eid:
        return ""
    r = con.execute("SELECT s.label || ':' || e.loc FROM events e JOIN sources s ON s.id=e.source_id WHERE e.id=?", (eid,)).fetchone()
    return r[0] if r else ""


def _sample(ids: list, cap) -> list:
    if not cap or len(ids) <= cap:
        return ids
    step = (len(ids) - 1) / max(1, cap - 1)
    return [ids[round(k * step)] for k in range(cap)]


def _record_desc(r, extra: list) -> str:
    word = KIND_WORD.get(r["kind"] or "", "Record")
    arrow = {"out": "to", "in": "from", "fwd": "forwarded from"}.get(r["dir"] or "", "with")
    name = f"{word} {arrow} {r['other']}" if r["other"] else word
    lines = [f"{r['ts_utc']} UTC - {name}",
             f"Direction: {r['dir'] or 'unknown'}; duration: {r['duration_s'] if r['duration_s'] is not None else '-'} s",
             f"Cell: {r['cell'] or '-'}" + (f" (ECI {r['eci']})" if r["eci"] is not None else "")
             + (f" - {r['site_name']}" if r["site_name"] else ""),
             f"Record: {r['cite']}", f"Site location: {r['loc_basis'] or 'not located'} {r['loc_cite'] or ''}",
             f"IMEI (first 14 digits): {r['imei'] or '-'}  IMSI: {r['imsi'] or '-'}"] + extra
    return name, "<br/>".join(_e(x) for x in lines)


def write_kml(case, con, params: dict) -> dict:
    out = case.exports_dir
    out.mkdir(parents=True, exist_ok=True)
    path = out / "telecom.kml"
    located = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE lat IS NOT NULL") or 0
    estimates = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE dev_lat IS NOT NULL") or 0
    if not located and not estimates:
        if path.exists():
            path.unlink()
        dbm.set_meta(con, "kml", None)
        return {}
    cap = int(params.get("kml_max_points", 20000))
    sector_km = float(params.get("kml_sector_km", 1.0))
    targets = [r[0] for r in con.execute("SELECT target FROM tel WHERE target IS NOT NULL AND lat IS NOT NULL AND src_kind != 'dump' "
                                         "GROUP BY target ORDER BY COUNT(*) DESC, target")]
    n_draw = located + estimates          # a timing-advance record is drawn twice: at its cell site and as an estimate
    per_cap = max(1, cap // max(1, len(targets) + 2)) if n_draw > cap else None
    L = ['<?xml version="1.0" encoding="UTF-8"?>', '<kml xmlns="http://www.opengis.net/kml/2.2">', "<Document>",
         f"<name>{_e('Spoor telecom - ' + case.name)}</name>",
         "<description>" + _e(
             "Draft for examiner review. Times are UTC. A record point is placed at the cell site that served it, NOT at "
             "the phone. Sector wedges are a drawing aid of fixed length, not coverage. 'Location estimates' are the "
             "carrier's estimates of the device position (timing advance, pings) with their stated confidence. "
             + (f"Capped: at most {per_cap} records per folder drawn; every record is in exports/telecom_records.csv. "
                if per_cap else "")) + "</description>"]
    L.append('<Style id="site"><IconStyle><color>ff333333</color><scale>0.8</scale></IconStyle>'
             '<LabelStyle><scale>0.7</scale></LabelStyle></Style>')
    L.append('<Style id="sector"><LineStyle><color>ff555555</color><width>1</width></LineStyle>'
             '<PolyStyle><color>33888888</color></PolyStyle></Style>')
    L.append('<Style id="coloc"><IconStyle><color>ff0000ff</color><scale>1.3</scale></IconStyle></Style>')
    L.append('<Style id="est"><IconStyle><color>ff00ffff</color><scale>0.6</scale></IconStyle>'
             '<LabelStyle><scale>0</scale></LabelStyle></Style>')
    L.append('<Style id="dump"><IconStyle><color>ff999999</color><scale>0.6</scale></IconStyle>'
             '<LabelStyle><scale>0</scale></LabelStyle></Style>')
    for i, t in enumerate(targets):
        L.append(f'<Style id="t{i}"><IconStyle><color>{PALETTE[i % len(PALETTE)]}</color><scale>0.9</scale></IconStyle>'
                 f'<LabelStyle><scale>0</scale></LabelStyle></Style>')
    # ---- cell sites the records used (one point per location; one wedge per distinct azimuth)
    sites: dict = {}
    for r in con.execute("SELECT cell, eci, lat, lon, azimuth, beamwidth, site_name, loc_event_id, loc_basis, COUNT(*) AS n "
                         "FROM tel WHERE lat IS NOT NULL GROUP BY round(lat, 5), round(lon, 5), cell, eci "
                         "ORDER BY round(lat, 5), round(lon, 5), cell"):
        k = (round(r["lat"], 5), round(r["lon"], 5))
        s = sites.setdefault(k, {"cells": {}, "name": r["site_name"], "lat": r["lat"], "lon": r["lon"]})
        s["name"] = s["name"] or r["site_name"]
        key = r["cell"] or (f"ECI {r['eci']}" if r["eci"] is not None else "?")
        if key not in s["cells"]:
            s["cells"][key] = (r["azimuth"], r["beamwidth"], r["loc_event_id"], r["loc_basis"], r["n"], r["eci"])
    L.append(f"<Folder><name>Cell sites used ({len(sites)})</name><open>0</open>")
    for (_la, _lo), s in sorted(sites.items()):
        cells = sorted(s["cells"].items())
        desc = "<br/>".join(
            _e(f"{c}" + (f" (ECI {eci})" if eci is not None else "") + f": azimuth {az if az is not None else '?'}, "
               f"beamwidth {bw if bw is not None else '? (60 drawn)'} - {basis} {_cite(con, eid)} - {n} record(s)")
            for c, (az, bw, eid, basis, n, eci) in cells)
        L.append(f'<Placemark><name>{_e(s["name"] or cells[0][0])}</name><styleUrl>#site</styleUrl>'
                 f"<description>{desc}</description><Point><coordinates>{s['lon']:.6f},{s['lat']:.6f},0</coordinates></Point></Placemark>")
        seen_az = set()
        for c, (az, bw, _eid, _b, _n, _eci) in cells:
            if az is None or (az, bw) in seen_az:
                continue
            seen_az.add((az, bw))
            L.append(f"<Placemark><name>{_e(c)}</name><styleUrl>#sector</styleUrl>"
                     f"<description>{_e(f'Sector {c}, azimuth {az}, beamwidth {bw or 60} (wedge length {sector_km} km is a drawing aid)')}</description>"
                     f"<Polygon><outerBoundaryIs><LinearRing><coordinates>{_wedge(s['lat'], s['lon'], az, bw, sector_km)}"
                     f"</coordinates></LinearRing></outerBoundaryIs></Polygon></Placemark>")
    L.append("</Folder>")
    drawn = 0
    # ---- per target (call records, timing advance and pings filed under a target; tower dumps are separate)
    for i, t in enumerate(targets):
        ids = _sample([r[0] for r in con.execute("SELECT event_id FROM tel WHERE target=? AND lat IS NOT NULL AND src_kind != 'dump' "
                                                 "ORDER BY ts_epoch, event_id", (t,))], per_cap)
        idset = set(ids)
        L.append(f"<Folder><name>{_e(t)} ({len(ids)} records at cell sites)</name><open>0</open>")
        for r in con.execute("SELECT * FROM calls WHERE target=? AND lat IS NOT NULL AND src_kind != 'dump' ORDER BY ts_utc, id", (t,)):
            if r["id"] not in idset:
                continue
            drawn += 1
            name, desc = _record_desc(r, [])
            when = _kml_time(r["ts_utc"])
            L.append(f"<Placemark><name>{_e(name)}</name>" + (f"<TimeStamp><when>{when}</when></TimeStamp>" if when else "")
                     + f"<styleUrl>#t{i}</styleUrl><description>{desc}</description>"
                     f"<Point><coordinates>{r['lon']:.6f},{r['lat']:.6f},0</coordinates></Point></Placemark>")
        L.append("</Folder>")
    # ---- location estimates (timing advance, pings): positions of the device, not of a cell site
    est_t = [r[0] for r in con.execute("SELECT COALESCE(target, '(no target)') FROM tel WHERE dev_lat IS NOT NULL "
                                       "GROUP BY 1 ORDER BY COUNT(*) DESC, 1")]
    if est_t:
        L.append("<Folder><name>Location estimates (device, not cell site)</name><open>0</open>")
        for t in est_t:
            ids = _sample([r[0] for r in con.execute("SELECT event_id FROM tel WHERE COALESCE(target, '(no target)')=? AND dev_lat IS NOT NULL "
                                                     "ORDER BY ts_epoch, event_id", (t,))], per_cap)
            idset = set(ids)
            L.append(f"<Folder><name>{_e(t)} ({len(ids)} estimates)</name><open>0</open>")
            for r in con.execute("SELECT * FROM calls WHERE COALESCE(target, '(no target)')=? AND dev_lat IS NOT NULL ORDER BY ts_utc, id", (t,)):
                if r["id"] not in idset:
                    continue
                drawn += 1
                what = "Timing advance" if r["src_kind"] == "ta" else "Ping"
                _n, desc = _record_desc(r, [f"{what} estimate of the DEVICE position: {r['dev_lat']}, {r['dev_lon']}"
                                            f"; confidence as given by the carrier: {r['dev_conf'] or 'not stated'}"])
                when = _kml_time(r["ts_utc"])
                L.append(f"<Placemark><name>{_e(what + ' ' + (r['ts_utc'] or ''))}</name>"
                         + (f"<TimeStamp><when>{when}</when></TimeStamp>" if when else "")
                         + f"<styleUrl>#est</styleUrl><description>{desc}</description>"
                         f"<Point><coordinates>{r['dev_lon']:.6f},{r['dev_lat']:.6f},0</coordinates></Point></Placemark>")
            L.append("</Folder>")
        L.append("</Folder>")
    # ---- tower dumps: one folder per source/section
    secs = dbm.rows(con, "SELECT t.source_id, COALESCE(t.section, '') AS section, s.label, s.display, COUNT(*) AS n, "
                         "SUM(t.lat IS NOT NULL) AS loc FROM tel t JOIN sources s ON s.id=t.source_id WHERE t.src_kind='dump' "
                         "GROUP BY t.source_id, section ORDER BY s.label, section")
    if secs:
        L.append("<Folder><name>Tower dumps</name><open>0</open>")
        for sec in secs:
            nm = f"{sec['label']} {sec['display'].replace(chr(92), '/').split('/')[-1]}" + (f" - {sec['section'][:80]}" if sec["section"] else "")
            L.append(f"<Folder><name>{_e(nm)} ({sec['loc']} of {sec['n']} records located)</name><open>0</open>")
            ids = _sample([r[0] for r in con.execute("SELECT event_id FROM tel WHERE src_kind='dump' AND source_id=? AND COALESCE(section,'')=? "
                                                     "AND lat IS NOT NULL ORDER BY ts_epoch, event_id", (sec["source_id"], sec["section"]))], per_cap)
            idset = set(ids)
            for r in con.execute("SELECT * FROM calls WHERE id IN (SELECT event_id FROM tel WHERE src_kind='dump' AND source_id=? "
                                 "AND COALESCE(section,'')=? AND lat IS NOT NULL) ORDER BY ts_utc, id", (sec["source_id"], sec["section"])):
                if r["id"] not in idset:
                    continue
                drawn += 1
                _n, desc = _record_desc(r, [f"Phone on the tower: {r['target']}"])
                when = _kml_time(r["ts_utc"])
                L.append(f"<Placemark><name>{_e(r['target'])}</name>" + (f"<TimeStamp><when>{when}</when></TimeStamp>" if when else "")
                         + f"<styleUrl>#dump</styleUrl><description>{desc}</description>"
                         f"<Point><coordinates>{r['lon']:.6f},{r['lat']:.6f},0</coordinates></Point></Placemark>")
            L.append("</Folder>")
        L.append("</Folder>")
    # ---- co-location occasions (from the findings, so the KML and the report agree)
    co = dbm.rows(con, "SELECT fid, facts FROM findings WHERE kind='telecom_colocation' ORDER BY sort_key, id")
    if co:
        L.append("<Folder><name>Co-location occasions</name><open>0</open>")
        for f in co:
            facts = json.loads(f["facts"] or "{}")
            v = facts.get("values", {})
            rows = (facts.get("tables") or [{}])[0].get("rows", [])
            for row, ids in zip(rows, facts.get("occasion_ids") or []):
                ts_a, cite_a, cell_a, ts_b, cite_b, cell_b, apart = row[:7]
                loc = con.execute("SELECT lat, lon FROM tel WHERE event_id=?", (ids[0],)).fetchone()
                if not loc or loc[0] is None:
                    continue
                desc = _e(f"{v.get('target_a')} at {ts_a} UTC on {cell_a} ({cite_a}); {v.get('target_b')} at {ts_b} UTC on {cell_b} "
                          f"({cite_b}); {apart} apart. Co-located cell sites - not proof the users were together. "
                          f"Finding {f['fid'] or ''}")
                L.append(f"<Placemark><name>{_e(str(v.get('target_a')) + ' + ' + str(v.get('target_b')))}</name>"
                         f"<TimeStamp><when>{_kml_time(ts_a)}</when></TimeStamp><styleUrl>#coloc</styleUrl>"
                         f"<description>{desc}</description><Point><coordinates>{loc[1]:.6f},{loc[0]:.6f},0</coordinates></Point></Placemark>")
        L.append("</Folder>")
    L.append("</Document></kml>")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    meta = {"file": "exports/telecom.kml", "records_drawn": drawn, "records_located": located, "estimates": estimates,
            "sites": len(sites), "capped_per_folder": per_cap, "sector_km": sector_km}
    dbm.set_meta(con, "kml", meta)
    return meta
