"""KML export of telecom records for Google Earth Pro / ArcGIS / QGIS (opens offline).

report/exports/telecom.kml:
  Cell sites    one point per site, a wedge per sector (azimuth +/- beamwidth/2). The wedge length
                is a fixed drawing aid (kml_sector_km), NOT a coverage estimate.
  <target>      one folder per target: every located call/text/data record, time-stamped (use the
                time slider), with the record's citation and the citation of its tower-list row.
  Co-location   one point per co-location occasion with both citations (from the analysis).
No external references: no icon URLs, no network links, no scripts. Deterministic output."""
from __future__ import annotations

import math
from xml.sax.saxutils import escape

from . import db as dbm

# KML colours are aabbggrr. Distinct, colour-blind-safer hues (Okabe-Ito order).
PALETTE = ["ff0072b2", "ff00a5e6", "ff73b409", "ff4294f0", "ffa779cc", "ff009ed5", "ffe9b456", "ff000000"]


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


def write_kml(case, con, params: dict) -> dict:
    out = case.exports_dir
    out.mkdir(parents=True, exist_ok=True)
    path = out / "telecom.kml"
    located = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE lat IS NOT NULL") or 0
    if not located and not (dbm.one(con, "SELECT COUNT(*) FROM cell_sites") or 0):
        if path.exists():
            path.unlink()
        dbm.set_meta(con, "kml", None)
        return {}
    cap = int(params.get("kml_max_points", 20000))
    sector_km = float(params.get("kml_sector_km", 1.0))
    targets = [r[0] for r in con.execute("SELECT target FROM tel WHERE target IS NOT NULL AND lat IS NOT NULL "
                                         "GROUP BY target ORDER BY COUNT(*) DESC, target")]
    per_cap = max(1, cap // max(1, len(targets))) if located > cap else None
    L = ['<?xml version="1.0" encoding="UTF-8"?>', '<kml xmlns="http://www.opengis.net/kml/2.2">', "<Document>",
         f"<name>{_e('Spoor telecom - ' + case.name)}</name>",
         "<description>" + _e(
             "Draft for examiner review. Times are UTC. Each point is a call/text/data record placed at the cell site "
             "named on the record, NOT the phone's position. Sector wedges are a drawing aid of fixed length, not coverage. "
             + (f"Capped: {per_cap} records per target drawn (of {located}); every record is in exports/telecom_records.csv. "
                if per_cap else "")) + "</description>"]
    L.append('<Style id="site"><IconStyle><color>ff333333</color><scale>0.8</scale></IconStyle>'
             '<LabelStyle><scale>0.7</scale></LabelStyle></Style>')
    L.append('<Style id="sector"><LineStyle><color>ff555555</color><width>1</width></LineStyle>'
             '<PolyStyle><color>33888888</color></PolyStyle></Style>')
    L.append('<Style id="coloc"><IconStyle><color>ff0000ff</color><scale>1.3</scale></IconStyle></Style>')
    for i, t in enumerate(targets):
        L.append(f'<Style id="t{i}"><IconStyle><color>{PALETTE[i % len(PALETTE)]}</color><scale>0.9</scale></IconStyle>'
                 f'<LabelStyle><scale>0</scale></LabelStyle></Style>')
    # ---- cell sites (one point per location; one wedge per distinct azimuth)
    sites: dict = {}
    for r in con.execute("SELECT cell, lat, lon, azimuth, beamwidth, site_name, event_id, origin FROM cell_sites "
                         "ORDER BY lat, lon, cell, id"):
        k = (round(r["lat"], 5), round(r["lon"], 5))
        s = sites.setdefault(k, {"cells": {}, "name": r["site_name"], "lat": r["lat"], "lon": r["lon"]})
        s["name"] = s["name"] or r["site_name"]
        if r["cell"] not in s["cells"]:
            s["cells"][r["cell"]] = (r["azimuth"], r["beamwidth"], r["event_id"], r["origin"])
    used = {r[0] for r in con.execute("SELECT DISTINCT cell FROM tel WHERE lat IS NOT NULL")}
    L.append("<Folder><name>Cell sites</name><open>0</open>")
    for (la, lo), s in sorted(sites.items()):
        cells = sorted(s["cells"].items())
        desc = "<br/>".join(
            _e(f"{c}: azimuth {az if az is not None else '?'}, beamwidth {bw if bw is not None else '? (60 drawn)'} - "
               f"{origin} {_cite(con, eid)}" + (" - used by a target" if c in used else ""))
            for c, (az, bw, eid, origin) in cells)
        L.append(f'<Placemark><name>{_e(s["name"] or cells[0][0])}</name><styleUrl>#site</styleUrl>'
                 f"<description>{desc}</description><Point><coordinates>{s['lon']:.6f},{s['lat']:.6f},0</coordinates></Point></Placemark>")
        seen_az = set()
        for c, (az, bw, eid, origin) in cells:
            if az is None or (az, bw) in seen_az:
                continue
            seen_az.add((az, bw))
            L.append(f"<Placemark><name>{_e(c)}</name><styleUrl>#sector</styleUrl>"
                     f"<description>{_e(f'Sector {c}, azimuth {az}, beamwidth {bw or 60} (wedge length {sector_km} km is a drawing aid)')}</description>"
                     f"<Polygon><outerBoundaryIs><LinearRing><coordinates>{_wedge(s['lat'], s['lon'], az, bw, sector_km)}"
                     f"</coordinates></LinearRing></outerBoundaryIs></Polygon></Placemark>")
    L.append("</Folder>")
    # ---- per target
    drawn = 0
    for i, t in enumerate(targets):
        ids = [r[0] for r in con.execute("SELECT event_id FROM tel WHERE target=? AND lat IS NOT NULL ORDER BY ts_epoch, event_id", (t,))]
        if per_cap and len(ids) > per_cap:
            step = (len(ids) - 1) / max(1, per_cap - 1)
            ids = [ids[round(k * step)] for k in range(per_cap)]
        idset = set(ids)
        L.append(f"<Folder><name>{_e(t)} ({len(ids)} records{' - sampled' if per_cap and len(idset) < located else ''})</name><open>0</open>")
        for r in con.execute("SELECT * FROM calls WHERE target=? AND lat IS NOT NULL ORDER BY ts_utc, id", (t,)):
            if r["id"] not in idset:
                continue
            drawn += 1
            when = _kml_time(r["ts_utc"])
            word = {"voice": "Call", "sms": "Text", "mms": "MMS", "data": "Data"}.get(r["kind"] or "", "Record")
            arrow = {"out": "to", "in": "from"}.get(r["dir"] or "", "with")
            name = f"{word} {arrow} {r['other']}" if r["other"] else word
            desc = "<br/>".join(_e(x) for x in [
                f"{r['ts_utc']} UTC - {name}",
                f"Direction: {r['dir'] or 'unknown'}; duration: {r['duration_s'] if r['duration_s'] is not None else '-'} s",
                f"Cell: {r['cell']} ({r['site_name'] or 'no site name'})" + (f"; last cell {r['cell_last']}" if r["cell_last"] and r["cell_last"] != r["cell"] else ""),
                f"Record: {r['cite']}", f"Site location: {r['loc_basis']} {r['loc_cite'] or ''}",
                f"IMEI: {r['imei'] or '-'}  IMSI: {r['imsi'] or '-'}"])
            L.append(f"<Placemark><name>{_e(name)}</name>" + (f"<TimeStamp><when>{when}</when></TimeStamp>" if when else "")
                     + f"<styleUrl>#t{i}</styleUrl><description>{desc}</description>"
                     f"<Point><coordinates>{r['lon']:.6f},{r['lat']:.6f},0</coordinates></Point></Placemark>")
        L.append("</Folder>")
    # ---- co-location occasions (from the findings, so the KML and the report agree)
    import json
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
    meta = {"file": "exports/telecom.kml", "records_drawn": drawn, "records_located": located, "sites": len(sites),
            "capped_per_target": per_cap, "sector_km": sector_km}
    dbm.set_meta(con, "kml", meta)
    return meta
