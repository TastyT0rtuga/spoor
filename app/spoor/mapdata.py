"""Telecom map data for the dashboard Map view and the GeoJSON export (plain data, no basemap, no network).

Points are the cell sites that served each record - NOT the phone's position. Device-position estimates (timing advance,
pings) are kept apart. Everything is read from the `tel` / `calls` tables; nothing is inferred."""
from __future__ import annotations

import json

from . import db as dbm


def status(con) -> dict:
    """Why a map is or is not available - used by the report, the dashboard and the CLI."""
    total = dbm.one(con, "SELECT COUNT(*) FROM tel") or 0
    located = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE lat IS NOT NULL") or 0
    est = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE dev_lat IS NOT NULL") or 0
    sites = dbm.one(con, "SELECT COUNT(*) FROM cell_sites") or 0
    s = {"telecom": bool(total), "records": total, "located": located, "estimates": est, "site_rows": sites, "map": bool(located or est)}
    if not total:
        s["reason"] = "The returns contain no telecom records."
    elif not (located or est):
        s["reason"] = (f"None of the {total:,} telecom records carries coordinates, and no cell-site list matched them"
                       + (f" ({sites:,} tower-list rows are loaded but none matched the cell identifiers in the records)." if sites else
                          " (no tower list is loaded). Add the carrier's cell-site list to the case and run again."))
    elif located < total:
        s["reason"] = f"{total - located:,} of {total:,} telecom records could not be placed (no matching cell-site coordinates); they are not on the map."
    return s


def map_data(con, params: dict, cap: int = 4000) -> dict:
    st = status(con)
    out = {"status": st, "sites": [], "targets": [], "estimates": [], "kml": dbm.get_meta(con, "kml")}
    if not st["map"]:
        return out
    sites: dict = {}
    for r in con.execute("SELECT cell, eci, lat, lon, azimuth, beamwidth, site_name, COUNT(*) AS n FROM tel WHERE lat IS NOT NULL "
                         "GROUP BY round(lat,5), round(lon,5), cell, eci ORDER BY round(lat,5), round(lon,5), cell"):
        k = (round(r["lat"], 5), round(r["lon"], 5))
        s = sites.setdefault(k, {"lat": r["lat"], "lon": r["lon"], "name": r["site_name"], "cells": [], "n": 0})
        s["name"] = s["name"] or r["site_name"]
        s["cells"].append({"cell": r["cell"] or (f"ECI {r['eci']}" if r["eci"] is not None else "?"), "az": r["azimuth"], "bw": r["beamwidth"], "n": r["n"]})
        s["n"] += r["n"]
    out["sites"] = list(sites.values())
    tg = [r[0] for r in con.execute("SELECT target FROM tel WHERE target IS NOT NULL AND lat IS NOT NULL AND src_kind != 'dump' "
                                    "GROUP BY target ORDER BY COUNT(*) DESC, target")]
    per = max(50, cap // max(1, len(tg)))
    for t in tg:
        rows = dbm.rows(con, "SELECT id, ts_utc, cell, lat, lon, kind, ret, cite FROM calls WHERE target=? AND lat IS NOT NULL AND src_kind != 'dump' "
                             "ORDER BY ts_utc, id", (t,))
        step = max(1, len(rows) // per) if len(rows) > per else 1
        out["targets"].append({"target": t, "records": len(rows), "drawn": len(rows[::step]),
                               "points": [[r["lat"], r["lon"], r["ts_utc"], r["cell"], r["ret"], r["cite"], r["kind"]] for r in rows[::step]]})
    est = dbm.rows(con, "SELECT ts_utc, dev_lat, dev_lon, dev_conf, target, ret, cite FROM calls WHERE dev_lat IS NOT NULL ORDER BY ts_utc, id LIMIT ?", (cap,))
    out["estimates"] = [[r["dev_lat"], r["dev_lon"], r["ts_utc"], r["dev_conf"], r["target"], r["ret"], r["cite"]] for r in est]
    return out


def write_geojson(case, con, params: dict) -> dict:
    """exports/telecom.geojson: cell sites used and the located records (a record sits at its cell site). For QGIS, ArcGIS, geojson.io (offline copies)."""
    path = case.exports_dir / "telecom.geojson"
    st = status(con)
    if not st["map"]:
        if path.exists():
            path.unlink()
        return {}
    d = map_data(con, params, cap=int(params.get("kml_max_points", 20000)))
    feats = []
    for s in d["sites"]:
        feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [round(s["lon"], 6), round(s["lat"], 6)]},
                      "properties": {"layer": "cell site used", "name": s["name"], "cells": [c["cell"] for c in s["cells"]], "records": s["n"]}})
    for t in d["targets"]:
        for la, lo, ts, cell, ret, cite, kind in t["points"]:
            feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [round(lo, 6), round(la, 6)]},
                          "properties": {"layer": "record at cell site", "target": t["target"], "time_utc": ts, "cell": cell, "kind": kind,
                                         "return": ret, "cite": cite, "note": "position of the serving cell site, not of the phone"}})
    for la, lo, ts, conf, tgt, ret, cite in d["estimates"]:
        feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [round(lo, 6), round(la, 6)]},
                      "properties": {"layer": "device estimate", "target": tgt, "time_utc": ts, "confidence": conf, "return": ret, "cite": cite,
                                     "note": "carrier's estimate of the device position"}})
    path.write_text(json.dumps({"type": "FeatureCollection", "features": feats}, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    meta = {"file": "exports/telecom.geojson", "features": len(feats)}
    dbm.set_meta(con, "geojson", meta)
    return meta
