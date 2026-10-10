"""Watchlist hits: compare the data with analyst-supplied lists (IPs, CIDR ranges, identifiers).

Lists live in <app>/watchlists/*.csv and <case>/watchlists/*.csv; one value per line, optional
label and note columns: value,label,note. Lines starting with # are comments."""
from __future__ import annotations

import csv
import hashlib
import ipaddress

from ..findings import plural
from ..identifiers import phone_from_cell
from ..ipaddr import normalize_ip
from ..util import app_root
from .base import T, Analysis


def load_watchlists(case) -> list[dict]:
    out = []
    for d in (app_root() / "watchlists", case.dir / "watchlists"):
        if not d.exists():
            continue
        for p in sorted(d.glob("*.csv")) + sorted(d.glob("*.txt")):
            if p.name.lower().startswith("readme"):
                continue   # instructions, not a list
            data = p.read_bytes()
            h = hashlib.sha256(data).hexdigest()
            text = data.decode("utf-8-sig", errors="replace")
            for i, row in enumerate(csv.reader(text.splitlines()), 1):
                if not row or not row[0].strip() or row[0].strip().startswith("#"):
                    continue
                v = row[0].strip()
                if v.lower() in ("value", "indicator", "ioc") and i == 1:
                    continue
                out.append({"file": p.name, "path": str(p), "sha256": h, "line": i, "value": v,
                            "label": row[1].strip() if len(row) > 1 else "", "note": row[2].strip() if len(row) > 2 else ""})
    return out


class Watchlist(Analysis):
    module = "watchlist"
    category = "Watchlist hits"

    def run(self):
        items = load_watchlists(self.case)
        if not items:
            return
        ip_rows = self.q("SELECT ip, ip_ver FROM ip_summary")
        for it in items:
            v = it["value"]
            where, args = None, ()
            try:
                if "/" in v and any(c.isdigit() for c in v):
                    net = ipaddress.ip_network(v, strict=False)
                    hits = [r["ip"] for r in ip_rows if ipaddress.ip_address(r["ip"]) in net]
                    if hits:
                        where = f"ip IN ({','.join('?' * len(hits))})"
                        args = tuple(hits)
                else:
                    n = normalize_ip(v)
                    if n:
                        where, args = "ip=?", (n[0],)
            except ValueError:
                pass
            if where is None and normalize_ip(v) is None and "/" not in v:
                norm = v.lower() if ("@" in v or v.lower().startswith(("0x", "bc1", "ltc1"))) else v
                ph = phone_from_cell(v)
                cands = [norm] + ([ph] if ph else [])
                ph_args = tuple(cands)
                where = (f"(id IN (SELECT event_id FROM identifiers WHERE norm IN ({','.join('?' * len(cands))})) "
                         f"OR lower(account) IN ({','.join('?' * len(cands))}))")
                args = ph_args + tuple(c.lower() for c in cands)
            if where is None:
                continue
            n = self.one(f"SELECT COUNT(*) FROM events WHERE {where}", args) or 0
            if not n:
                continue
            r = self.q(f"SELECT MIN(ts_utc) AS f, MAX(ts_utc) AS l, COUNT(DISTINCT account) AS a, GROUP_CONCAT(DISTINCT source_id) AS s "
                       f"FROM events WHERE {where}", args)[0]
            srcs = self.labels((r["s"] or "").split(",")) if r["s"] else ""
            cite = f"{it['file']}:L{it['line']}"
            stmt = (f"Watchlist {cite} ({it['value']}" + (f", '{it['label']}'" if it["label"] else "") + f") matches {plural(n, 'record')}"
                    + (f" for {plural(r['a'], 'account')}" if r["a"] else "") + (f" in {srcs}" if srcs else "")
                    + (f" between {T(r['f'])} and {T(r['l'])}" if r["f"] else "") + ".")
            self.add("watchlist_hit", f"Watchlist hit: {it['value']}", stmt,
                     {"values": {"watchlist": it["file"], "line": it["line"], "value": it["value"], "label": it["label"],
                                 "note": it["note"], "records": n, "accounts": r["a"], "sources": srcs,
                                 "first_utc": r["f"], "last_utc": r["l"], "watchlist_sha256": it["sha256"]}},
                     evidence=self.sample(where, args, 8), priority=1, sort_key=f"{it['file']}{it['line']:08d}",
                     cites=[{"cite": cite, "source_id": None, "loc": f"L{it['line']}", "text": it["value"],
                             "expect": it["value"], "path": it["path"]}])
