"""Figure 3 - target-contact chart (telecom returns).

The target numbers either side; in the middle every number in contact with two or more targets
(a "common contact" finding) and one node per pair of targets in direct contact (a "direct contact"
finding). A line joins a target to a middle node, labelled with that target's records with that
number (exports/telecom_contacts.csv). Any number of returns is drawn at once. The most widely
shared contact is the only thing in the accent colour."""
from __future__ import annotations

from .. import db as dbm
from .common import Ctx, Figure, Ref, fmt_n
from .linkchart import _arrange, _crossings, _ports
from .svg import ACCENT, INK, MUTED, PAPER, RULE, SOFT, Svg, c4, f4, fit, text_width, wrap

W = 800
MARGIN = 24
ACC_W = 208
MID_W = 176
L_X = MARGIN
MID_X = (W - MID_W) // 2
R_X = W - MARGIN - ACC_W
PORT = 24
NODE_GAP = 12


def build(ctx: Ctx) -> Figure:
    fig = Figure(3, "contacts", "Target-contact chart")
    p = ctx.p
    max_t = max(2, int(p.get("figure_contacts_max_targets", 12)))
    max_m = max(1, int(p.get("figure_contacts_max_contacts", 16)))
    fig.caps = {"figure_contacts_max_targets": max_t, "figure_contacts_max_contacts": max_m}
    commons = ctx.of_kind("telecom_common")
    directs = ctx.of_kind("telecom_direct")
    if not commons and not directs:
        fig.status, fig.reason = "skipped", "no telecom targets share a contact or contacted each other"
        return fig
    con = ctx.con
    totals = {r["target"]: r for r in dbm.rows(con, "SELECT target, COUNT(*) AS n, COUNT(DISTINCT other) AS c FROM tel "
                                                    "WHERE target IS NOT NULL GROUP BY target")}
    # middle nodes: direct-contact pairs first (each names two targets), then common contacts, widest first
    mids = []
    for f in directs:
        v = f["values"]
        a, b = v.get("target_a"), v.get("target_b")
        edges = {r["target"]: r["n"] for r in dbm.rows(
            con, "SELECT target, COUNT(*) AS n FROM tel WHERE (target=? AND other=?) OR (target=? AND other=?) GROUP BY target",
            (a, b, b, a))}
        mids.append({"key": f"{a}|{b}", "kind": "direct", "f": f, "label": "direct contact", "targets": [a, b],
                     "edges": {a: edges.get(a, 0), b: edges.get(b, 0)}, "records": v.get("records", 0)})
    for f in commons:
        v = f["values"]
        o = v.get("other")
        edges = {r["target"]: r["n"] for r in dbm.rows(con, "SELECT target, COUNT(*) AS n FROM tel WHERE other=? AND target IS NOT NULL "
                                                            "GROUP BY target", (o,))}
        mids.append({"key": o, "kind": "common", "f": f, "label": o, "targets": sorted(edges), "edges": edges,
                     "records": sum(edges.values())})
    # targets: those on the most middle nodes first
    deg: dict = {}
    for m in mids:
        for t in m["targets"]:
            deg[t] = deg.get(t, 0) + 1
    rank = sorted(deg, key=lambda t: (-deg[t], -(totals.get(t) or {"n": 0})["n"], t))
    keep_t = set(rank[:max_t])
    notes: list[str] = []
    cand = [m for m in mids if sum(1 for t in m["targets"] if t in keep_t) >= 2]
    cand.sort(key=lambda m: (m["kind"] != "direct", -sum(1 for t in m["targets"] if t in keep_t), -m["records"], m["key"]))
    drawn = cand[:max_m]
    hot = None
    widest = [m for m in drawn if m["kind"] == "common"]
    if widest:
        top_n = max(len(m["targets"]) for m in widest)
        if top_n >= 3:
            hot = min((m for m in widest if len(m["targets"]) == top_n), key=lambda m: (-m["records"], m["key"]))["key"]
    tdrawn = sorted({t for m in drawn for t in m["targets"] if t in keep_t})
    if len(drawn) < len(mids) or len(tdrawn) < len(deg):
        notes.append(f"Showing {len(drawn)} of {len(mids)} shared contacts / direct-contact pairs and {len(tdrawn)} of {len(deg)} targets "
                     "(direct contact first, then contacts shared by the most drawn targets); every pair is in exports/common_contacts.csv "
                     "and exports/telecom_contacts.csv.")
    edges = []
    for m in drawn:
        for t in m["targets"]:
            if t in keep_t:
                edges.append((t, m["key"], m["edges"].get(t, 0)))
    acc_ips: dict = {}
    ip_accs: dict = {}
    for t, k, _n in edges:
        acc_ips.setdefault(t, []).append(k)
        ip_accs.setdefault(k, []).append(t)
    keys = [m["key"] for m in drawn]
    order = sorted(tdrawn, key=lambda a: (-len(acc_ips[a]), -(totals.get(a) or {"n": 0})["n"], a))
    best = None
    if len(order) <= 10:
        for mask in range(1 << max(0, len(order) - 1)):
            left = [a for i, a in enumerate(order) if i == 0 or not (mask >> (i - 1)) & 1]
            right = [a for i, a in enumerate(order) if i > 0 and (mask >> (i - 1)) & 1]
            lo, ro, io = _arrange(left, right, keys, acc_ips, ip_accs)
            score = (_crossings(lo, io, acc_ips) + _crossings(ro, io, acc_ips), abs(len(lo) - len(ro)), mask)
            if best is None or score < best[0]:
                best = (score, lo, ro, io)
        _, left, right, mid_ord = best
    else:
        left, right, mid_ord = _arrange([a for i, a in enumerate(order) if i % 2 == 0],
                                        [a for i, a in enumerate(order) if i % 2 == 1], keys, acc_ips, ip_accs)
    side = {a: "L" for a in left}
    side.update({a: "R" for a in right})
    bykey = {m["key"]: m for m in drawn}

    def t_h(a):
        return max(48, PORT * len(acc_ips[a]) + 8)

    def m_h(k):
        nl_ports = max(sum(1 for a in ip_accs[k] if side[a] == "L"), sum(1 for a in ip_accs[k] if side[a] == "R"))
        h = max(8 + 16 * 2 + 4, PORT * nl_ports + 8, 48)
        return int(-(-h // 8) * 8)
    cols = {"L": [(a, t_h(a)) for a in left], "M": [(k, m_h(k)) for k in mid_ord], "R": [(a, t_h(a)) for a in right]}
    heights = {c: sum(h for _, h in items) + NODE_GAP * max(0, len(items) - 1) for c, items in cols.items()}
    inner = max(heights.values())
    y0 = 80
    pos = {}
    for c, items in cols.items():
        y = y0 + f4((inner - heights[c]) / 2)
        for key, h in items:
            pos[(c, key)] = (y, h)
            y += h + NODE_GAP
    notes.append("Each line joins a target to a number both targets were in contact with (or, for 'direct contact', to the other target); "
                 "the number on the line is that target's records with that number (exports/telecom_contacts.csv); a dashed line "
                 "labelled 0 means the contact appears only in the other target's records. "
                 "The accent marks the contact shared by the most targets.")
    note_lines = []
    for n_ in notes:
        note_lines += wrap(n_, "mono", W - 2 * MARGIN)
    y_notes = y0 + inner + 32
    H = c4(y_notes + len(note_lines) * 16 + 12)
    desc = (f"{len(tdrawn)} target number(s) and {len(drawn)} shared contact(s) or direct-contact pair(s). Lines are labelled with record "
            f"counts. Case {ctx.case.name}.")
    s = Svg("fig03", W, H, "Figure 3. Target-contact chart", desc)
    s.text(MARGIN, 36, "Target–contact chart", "title")
    sub = f"{ctx.case.name} · {len(tdrawn)} targets · shared contacts and direct contact"
    s.text(MARGIN, 56, fit(sub, "mono", W - 2 * MARGIN), "mono", fill=MUTED, tip=sub)
    centers = {}
    for a in left + right:
        c = side[a]
        yy, h = pos[(c, a)]
        x = L_X if c == "L" else R_X
        tot = totals.get(a) or {"n": 0, "c": 0}
        s.open({"class": "node"}, tip=f"Target {a}: {fmt_n(tot['n'])} records, {fmt_n(tot['c'])} other numbers in the case")
        s.rect(x, yy, ACC_W, h, fill=SOFT, stroke=RULE, rx=8)
        s.text(x + 12, yy + 20, fit(a, "label", ACC_W - 24), "label", fill=INK)
        s.text(x + 12, yy + 36, fit(f"{fmt_n(tot['n'])} recs · {fmt_n(tot['c'])} numbers", "mono", ACC_W - 24), "mono", fill=MUTED)
        s.close()
        centers[a] = (x, yy, h)
    box = {}
    for k in mid_ord:
        m = bykey[k]
        yy, h = pos[("M", k)]
        fid = m["f"]["fid"]
        isdirect = m["kind"] == "direct"
        col = ACCENT if k == hot else INK
        s.open({"class": "node", "data-finding": fid}, tip=f"{fid}: {m['f']['statement']}")
        s.rect(MID_X, yy, MID_W, h, fill=PAPER, stroke=col, rx=4 if not isdirect else 8, dash=None if not isdirect else "4 4")
        s.text(MID_X + 8, yy + 20, fit(m["label"], "mono" if not isdirect else "label", MID_W - 16), "mono" if not isdirect else "label",
               fill=col)
        sub = f"{fid} · {len(m['targets'])} targets" if not isdirect else f"{fid} · {fmt_n(m['records'])} records"
        s.text(MID_X + 8, yy + 36, fit(sub, "mono", MID_W - 16), "mono", fill=MUTED if k != hot else ACCENT)
        s.close()
        box[k] = (yy, h)
        first = dbm.one(con, "SELECT event_id FROM tel WHERE " + (
            "(target=? AND other=?) OR (target=? AND other=?)" if isdirect else "other=? AND target IN (" + ",".join("?" * len(m["targets"])) + ")")
            + " ORDER BY ts_epoch IS NULL, ts_epoch, event_id LIMIT 1",
            (m["targets"][0], m["targets"][1], m["targets"][1], m["targets"][0]) if isdirect else (k, *m["targets"]))
        fig.refs.append(Ref(fid, fid, ("direct contact between " + " and ".join(m["targets"])) if isdirect
                            else f"{k} in contact with {len(m['targets'])} targets", cite=ctx.cite(first)))
    acc_port = {}
    for a in left + right:
        x, yy, h = centers[a]
        ks = sorted(acc_ips[a], key=lambda k: (box[k][0] + box[k][1] // 2, k))
        for k, py in zip(ks, _ports(yy + h // 2, len(ks))):
            acc_port[(a, k)] = py
    mid_port = {}
    for k in mid_ord:
        yy, h = box[k]
        for c in ("L", "R"):
            accs = sorted([a for a in ip_accs[k] if side[a] == c], key=lambda a: (acc_port[(a, k)], a))
            for a, py in zip(accs, _ports(yy + h // 2, len(accs))):
                mid_port[(a, k)] = py
    for t, k, n in sorted(edges, key=lambda e: (e[0], e[1])):
        col = ACCENT if k == hot else INK
        ay, iy = acc_port[(t, k)], mid_port[(t, k)]
        lab = fmt_n(n)
        pw = max(24, int(-(-(text_width(lab, "mono") + 8) // 8)) * 8)
        m = bykey[k]
        other = [x for x in m["targets"] if x != t][0] if m["kind"] == "direct" else k
        first = dbm.one(con, "SELECT event_id FROM tel WHERE target=? AND other=? ORDER BY ts_epoch IS NULL, ts_epoch, event_id LIMIT 1",
                        (t, other))
        cite = ctx.cite(first)
        tip = f"{m['f']['fid']} · {t}: {fmt_n(n)} record{'s' if n != 1 else ''} with {other}" + (f"; first {cite}" if cite else "")
        if not n:
            tip += " (the contact appears only in the other target's records)"
        dash = "4 4" if not n else None
        if side[t] == "L":
            xb = L_X + ACC_W
            s.line(xb, ay, xb + 8, ay, stroke=col, tip=tip, dash=dash)
            px = xb + 8
            s.line(px + pw, ay, MID_X, iy, stroke=col, tip=tip, dash=dash)
        else:
            xb = R_X
            px = xb - 8 - pw
            s.line(px + pw, ay, xb, ay, stroke=col, tip=tip, dash=dash)
            s.line(MID_X + MID_W, iy, px, ay, stroke=col, tip=tip, dash=dash)
        s.pill(px, ay - 8, lab, fill=PAPER, stroke=col, color=col, tip=tip, min_w=pw,
               attrs={"class": "cite", "data-cite": cite} if cite else None)
    for i, line in enumerate(note_lines):
        s.text(MARGIN, y_notes + i * 16, line, "mono", fill=MUTED)
    fig.svg = s.render()
    fig.notes = notes
    fig.caption = ("Target numbers either side; in the middle, numbers in contact with two or more targets and pairs of targets in direct "
                   "contact. Each line is labelled with that target's records with that number. The contact shared by the most targets is "
                   "in the accent colour.")
    tl = ", ".join("'" + t.replace("'", "''") + "'" for t in tdrawn)
    fig.data_sql.append(("lines and labels", f"SELECT target, other, COUNT(*) AS records FROM tel WHERE target IN ({tl}) AND other IS NOT NULL "
                                             f"GROUP BY target, other HAVING other IN (SELECT other FROM tel WHERE target IN ({tl}) GROUP BY other "
                                             f"HAVING COUNT(DISTINCT target) >= 2) OR other IN ({tl}) ORDER BY target, other"))
    fig.meta = {"targets": tdrawn, "middle": [bykey[k]["key"] for k in mid_ord], "edges": sorted([list(e) for e in edges]), "hot": hot}
    return fig
