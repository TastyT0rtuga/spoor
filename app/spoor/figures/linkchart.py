"""Figure 2 - account-IP link chart.

One panel per "accounts linked by shared IPs" finding: the shared IPs in the middle, the accounts
either side, a line wherever an account used an IP, labelled with that account's number of records
on that IP (the link-chart edges in exports/link_edges.csv and exports/ip_accounts.csv). The closest
co-use the finding reports - two accounts on one IP closest in time - is the only thing in the accent
colour."""
from __future__ import annotations

from .. import db as dbm
from .common import Ctx, Figure, Ref, fmt_n
from .svg import ACCENT, INK, MUTED, PAPER, RULE, SOFT, Svg, c4, f4, fit, text_width, wrap

W = 800
MARGIN = 24
ACC_W = 208
IP_W = 176
L_X = MARGIN
IP_X = (W - IP_W) // 2
R_X = W - MARGIN - ACC_W
PORT = 24
NODE_GAP = 12


def _ip_lines(ip: str) -> list[str]:
    if text_width(ip, "mono") <= IP_W - 16:
        return [ip]
    best = None
    for i, ch in enumerate(ip):
        if ch == ":":
            a, b = ip[: i + 1], ip[i + 1:]
            score = abs(len(a) - len(b))
            if text_width(a, "mono") <= IP_W - 16 and text_width(b, "mono") <= IP_W - 16 and (best is None or score < best[0]):
                best = (score, [a, b])
    return best[1] if best else [fit(ip, "mono", IP_W - 16)]


def _net(row) -> str:
    if not row:
        return ""
    bits = []
    if row["asn"]:
        bits.append(f"AS{row['asn']}")
    if row["country"]:
        bits.append(row["country"])
    return " · ".join(bits) if bits else (row["ip_class"] or "")


def build(ctx: Ctx) -> Figure:
    fig = Figure(2, "links", "Account-IP link chart")
    p = ctx.p
    max_panels = max(1, int(p.get("figure_links_max_clusters", 3)))
    max_acc = max(2, int(p.get("figure_links_max_accounts", 12)))
    max_ips = max(1, int(p.get("figure_links_max_ips", 16)))
    fig.caps = {"figure_links_max_clusters": max_panels, "figure_links_max_accounts": max_acc, "figure_links_max_ips": max_ips}
    clusters = ctx.of_kind("account_cluster")
    if not clusters:
        fig.status, fig.reason = "skipped", "no accounts are linked by shared IPs"
        return fig
    con = ctx.con
    notes: list[str] = []
    if len(clusters) > max_panels:
        notes.append(f"Showing {max_panels} of {len(clusters)} linked groups (largest first); the others: "
                     + ", ".join(f["fid"] for f in clusters[max_panels:max_panels + 20])
                     + (f" and {len(clusters) - max_panels - 20} more" if len(clusters) > max_panels + 20 else "")
                     + "; every edge is in exports/link_edges.csv.")
    panels = []
    for k, f in enumerate(clusters[:max_panels], 1):
        g = f["facts"].get("graph") or {}
        accounts = list(g.get("accounts") or f["values"].get("accounts") or [])
        ips = list(g.get("ips") or [])
        if not ips:
            continue
        v = f["values"]
        edges = []
        for i in range(0, len(ips), 500):
            part = ips[i:i + 500]
            edges += dbm.rows(con, f"SELECT ip, account, events, first_utc, last_utc, first_id FROM ip_accounts WHERE ip IN "
                                   f"({','.join('?' * len(part))})", part)
        accset = set(accounts)
        edges = [e for e in edges if e["account"] in accset]
        deg: dict = {}
        recs: dict = {}
        for e in edges:
            deg[e["account"]] = deg.get(e["account"], 0) + 1
            recs[e["account"]] = recs.get(e["account"], 0) + e["events"]
        must = [a for a in (v.get("closest_a"), v.get("closest_b")) if a in accset]
        rank = sorted(accset, key=lambda a: (a not in must, -deg.get(a, 0), -recs.get(a, 0), a))
        keep_acc = set(rank[:max_acc])
        ip_acc: dict = {}
        ip_rec: dict = {}
        for e in edges:
            if e["account"] in keep_acc:
                ip_acc.setdefault(e["ip"], set()).add(e["account"])
                ip_rec[e["ip"]] = ip_rec.get(e["ip"], 0) + e["events"]
        cand = [ip for ip, s in ip_acc.items() if len(s) >= 2]
        cand.sort(key=lambda ip: (ip != v.get("closest_ip"), -len(ip_acc[ip]), -ip_rec[ip], ip))
        keep_ip = set(cand[:max_ips])
        es = [e for e in edges if e["account"] in keep_acc and e["ip"] in keep_ip]
        acc_drawn = sorted({e["account"] for e in es})
        if len(acc_drawn) < len(accounts) or len(keep_ip) < len(ips):
            notes.append(f"Panel {k} ({f['fid']}): showing {len(acc_drawn)} of {len(accounts)} accounts and {len(keep_ip)} of {len(ips)} "
                         "shared IPs (accounts with the most shared IPs first; IPs used by the most drawn accounts first).")
        panels.append({"k": k, "f": f, "acc": acc_drawn, "ips": sorted(keep_ip), "edges": es, "v": v,
                       "n_acc": len(accounts), "n_ip": len(ips)})
    if not panels:
        fig.status, fig.reason = "skipped", "linked groups carry no IP list (re-run the analysis with this version)"
        return fig

    totals = {r["account"]: r for r in dbm.rows(con, "SELECT account, events, ips FROM account_summary")}
    ipinfo = {}
    for pn in panels:
        for i in range(0, len(pn["ips"]), 500):
            part = pn["ips"][i:i + 500]
            for r in dbm.rows(con, f"SELECT ip, ip_class, asn, as_org, country, events, accounts FROM ip_summary WHERE ip IN "
                                   f"({','.join('?' * len(part))})", part):
                ipinfo[r["ip"]] = r

    # ------------------------------------------------------------ layout per panel
    for pn in panels:
        _layout(pn, totals, ipinfo)

    classes = (panels[0]["f"]["facts"].get("graph") or {}).get("ip_classes", "")
    maxper = (panels[0]["f"]["facts"].get("graph") or {}).get("max_accounts_per_ip", p.get("shared_ip_max_accounts", 25))
    notes.append("Each line joins an account to an IP address it used; the number on the line is that account's records on that IP "
                 f"(exports/ip_accounts.csv). Accounts are linked when they used the same IP; IPs used by more than {maxper} accounts are "
                 "treated as shared infrastructure and do not link" + (f"; address classes that link: {classes.strip('()').replace(chr(39), '').replace(',', ', ')}" if classes else "")
                 + ". The accent marks the closest co-use each finding reports.")
    note_lines = []
    for n_ in notes:
        note_lines += wrap(n_, "mono", W - 2 * MARGIN)

    y_title, y_sub = 36, 56
    y = 80
    for pn in panels:
        pn["y0"] = y
        y = y + pn["h"] + 24
    y_notes = y + 8
    H = c4(y_notes + len(note_lines) * 16 + 12)
    n_acc = len({a for pn in panels for a in pn["acc"]})
    desc = (f"{len(panels)} group(s) of accounts linked by shared IP addresses, {n_acc} account(s) drawn. Lines join accounts to the IPs "
            f"they used, labelled with record counts. Case {ctx.case.name}.")
    s = Svg("fig02", W, H, "Figure 2. Account-IP link chart", desc)
    s.text(MARGIN, y_title, "Account–IP link chart", "title")
    sub = f"{ctx.case.name} · {len(panels)} linked group(s) · accounts that used the same IP addresses"
    s.text(MARGIN, y_sub, fit(sub, "mono", W - 2 * MARGIN), "mono", fill=MUTED, tip=sub)
    for pn in panels:
        _draw(s, pn, fig, ctx)
    for i, line in enumerate(note_lines):
        s.text(MARGIN, y_notes + i * 16, line, "mono", fill=MUTED)
    fig.svg = s.render()
    fig.notes = notes
    fig.caption = ("Accounts linked by shared IP addresses: shared IPs in the middle, accounts either side, each line labelled with the "
                   "account's number of records on that IP. One panel per linked-group finding; the closest co-use it reports is in the accent colour.")
    fig.meta = {"panels": [{"fid": pn["f"]["fid"], "accounts": pn["acc"], "ips": pn["ips"],
                            "edges": sorted([e["account"], e["ip"], e["events"]] for e in pn["edges"])} for pn in panels]}
    return fig


def _layout(pn: dict, totals: dict, ipinfo: dict) -> None:
    es = pn["edges"]
    v = pn["v"]
    acc_ips: dict = {}
    ip_accs: dict = {}
    for e in es:
        acc_ips.setdefault(e["account"], []).append(e["ip"])
        ip_accs.setdefault(e["ip"], []).append(e["account"])
    order = sorted(pn["acc"], key=lambda a: (-len(acc_ips[a]), -totals.get(a, {"events": 0})["events"], a))
    best = None
    if len(order) <= 10:
        # try every split of the accounts into the two sides; keep the one with the fewest crossing lines
        for mask in range(1 << (len(order) - 1)):            # the first account always on the left
            left = [a for i, a in enumerate(order) if i == 0 or not (mask >> (i - 1)) & 1]
            right = [a for i, a in enumerate(order) if i > 0 and (mask >> (i - 1)) & 1]
            lo, ro, io = _arrange(left, right, pn["ips"], acc_ips, ip_accs)
            score = (_crossings(lo, io, acc_ips) + _crossings(ro, io, acc_ips), abs(len(lo) - len(ro)), mask)
            if best is None or score < best[0]:
                best = (score, lo, ro, io)
    if best is None:
        left = [a for i, a in enumerate(order) if i % 2 == 0]
        right = [a for i, a in enumerate(order) if i % 2 == 1]
        left, right, ips = _arrange(left, right, pn["ips"], acc_ips, ip_accs)
    else:
        _, left, right, ips = best
    side = {a: "L" for a in left}
    side.update({a: "R" for a in right})

    def acc_h(a):
        return max(48, PORT * len(acc_ips[a]) + 8)
    ip_lines = {ip: _ip_lines(ip) for ip in ips}
    closest_ip = v.get("closest_ip") if v.get("closest_a") in side and v.get("closest_b") in side else None

    def ip_h(ip):
        nl = len(ip_lines[ip]) + 1 + (1 if ip == closest_ip else 0)
        content = 8 + 16 * nl
        nl_ports = max(sum(1 for a in ip_accs[ip] if side[a] == "L"), sum(1 for a in ip_accs[ip] if side[a] == "R"))
        h = max(content + 4, PORT * nl_ports + 8, 48)
        return int(-(-h // 8) * 8)          # multiple of 8 so the port centre stays on the grid
    cols = {"L": [(a, acc_h(a)) for a in left], "M": [(ip, ip_h(ip)) for ip in ips], "R": [(a, acc_h(a)) for a in right]}
    heights = {c: sum(h for _, h in items) + NODE_GAP * max(0, len(items) - 1) for c, items in cols.items()}
    inner = max(heights.values())
    top = 64 if v.get("closest_a") else 40   # header rows
    pos = {}
    for c, items in cols.items():
        y = top + f4((inner - heights[c]) / 2)
        for key, h in items:
            pos[(c, key)] = (y, h)
            y += h + NODE_GAP
    pn.update({"left": left, "right": right, "ips_ord": ips, "side": side, "pos": pos, "acc_ips": acc_ips, "ip_accs": ip_accs,
               "ip_lines": ip_lines, "closest_ip": closest_ip, "h": top + inner + 16, "ipinfo": ipinfo, "totals": totals})


def _norm(lst: list) -> dict:
    n = len(lst)
    return {x: (i / (n - 1) if n > 1 else 0.5) for i, x in enumerate(lst)}


def _arrange(left: list, right: list, ips: list, acc_ips: dict, ip_accs: dict) -> tuple[list, list, list]:
    """Barycentre ordering: accounts follow the mean position of their IPs and IPs that of their accounts."""
    left, right = list(left), list(right)
    ips = sorted(ips, key=lambda ip: (-len(ip_accs[ip]), ip))
    for _ in range(8):
        ipos = _norm(ips)
        left.sort(key=lambda a: (sum(ipos[i] for i in acc_ips[a]) / len(acc_ips[a]), a))
        right.sort(key=lambda a: (sum(ipos[i] for i in acc_ips[a]) / len(acc_ips[a]), a))
        apos = dict(_norm(left), **_norm(right))
        ips.sort(key=lambda ip: (sum(apos[a] for a in ip_accs[ip] if a in apos) / max(1, sum(1 for a in ip_accs[ip] if a in apos)), ip))
    return left, right, ips


def _crossings(accs: list, ips: list, acc_ips: dict) -> int:
    ai = {a: i for i, a in enumerate(accs)}
    ii = {ip: i for i, ip in enumerate(ips)}
    es = sorted((ai[a], ii[ip]) for a in accs for ip in acc_ips[a])
    n = 0
    for k, (a1, i1) in enumerate(es):
        for a2, i2 in es[k + 1:]:
            if a2 > a1 and i2 < i1:
                n += 1
    return n


def _ports(cy: int, n: int) -> list[int]:
    return [cy - 12 * (n - 1) + PORT * i for i in range(n)]


def _draw(s: Svg, pn: dict, fig: Figure, ctx: Ctx) -> None:
    f, v, y0 = pn["f"], pn["v"], pn["y0"]
    fid = f["fid"]
    pos, side = pn["pos"], pn["side"]
    # header
    s.rect(MARGIN, y0, W - 2 * MARGIN, pn["h"], fill="none", stroke=RULE, rx=8)
    s.text(MARGIN + 12, y0 + 24, fid, "mono", fill=INK, attrs={"data-finding": fid}, tip=f"{fid}: {f['statement']}")
    hdr = f"{len(pn['acc'])} of {pn['n_acc']} accounts · {len(pn['ips'])} of {pn['n_ip']} shared IPs" \
        if (len(pn["acc"]) < pn["n_acc"] or len(pn["ips"]) < pn["n_ip"]) else f["title"]
    hx = MARGIN + 12 + c4(text_width(fid, "mono") + 12)
    s.text(hx, y0 + 24, fit(hdr, "label", W - MARGIN - 12 - hx), "label", fill=INK)
    if v.get("closest_a"):
        ta, tb = str(v.get("closest_ts_a") or ""), str(v.get("closest_ts_b") or "")
        if ta[:10] == tb[:10] and len(ta) > 10 and len(tb) > 10:
            cl = f"closest co-use {ta[:10]}: {v['closest_a']} {ta[11:]} and {v['closest_b']} {tb[11:]} UTC"
        else:
            cl = f"closest co-use: {v['closest_a']} {ta} and {v['closest_b']} {tb} UTC"
        full = (f"Closest co-use: {v['closest_a']} at {ta} and {v['closest_b']} at {tb} UTC on {v.get('closest_ip')} "
                f"({v.get('closest')} apart)")
        s.text(hx, y0 + 44, fit(cl, "mono", W - MARGIN - 12 - hx), "mono", fill=MUTED, tip=full)
    closest_cite = None
    # nodes: accounts
    centers: dict = {}
    for a in pn["left"] + pn["right"]:
        c = side[a]
        yy, h = pos[(c, a)]
        yy += y0
        x = L_X if c == "L" else R_X
        tot = pn["totals"].get(a) or {"events": 0, "ips": 0}
        tip = f"{fid} · {a}: {fmt_n(tot['events'])} records in the case, {fmt_n(tot['ips'] or 0)} IPs; {len(pn['acc_ips'][a])} shared IP(s) in this group"
        s.open({"class": "node"}, tip=tip)
        s.rect(x, yy, ACC_W, h, fill=SOFT, stroke=RULE, rx=8)
        s.text(x + 12, yy + 20, fit(a, "label", ACC_W - 24), "label", fill=INK)
        nips = tot["ips"] or 0
        s.text(x + 12, yy + 36, fit(f"{fmt_n(tot['events'])} records · {fmt_n(nips)} IP{'s' if nips != 1 else ''}", "mono", ACC_W - 24),
               "mono", fill=MUTED)
        s.close()
        centers[a] = (x, yy, h)
    ip_box = {}
    for ip in pn["ips_ord"]:
        yy, h = pos[("M", ip)]
        yy += y0
        info = pn["ipinfo"].get(ip) or {}
        net = _net(info)
        tip = (f"{fid} · {ip}: {info.get('ip_class', '')}" + (f", AS{info['asn']} {info.get('as_org') or ''}" if info.get("asn") else "")
               + (f", {info['country']}" if info.get("country") else "") + f"; {fmt_n(info.get('events') or 0)} records, "
               f"{fmt_n(info.get('accounts') or 0)} accounts in the case")
        s.open({"class": "node"}, tip=tip)
        s.rect(IP_X, yy, IP_W, h, fill=PAPER, stroke=INK, rx=4)
        ty = yy + 20
        for line in pn["ip_lines"][ip]:
            s.text(IP_X + 8, ty, line, "mono", fill=INK)
            ty += 16
        s.text(IP_X + 8, ty, fit(net, "mono", IP_W - 16), "mono", fill=MUTED)
        ty += 16
        if ip == pn["closest_ip"]:
            s.text(IP_X + 8, ty, fit(f"closest: {v.get('closest')}", "mono", IP_W - 16), "mono", fill=ACCENT)
        s.close()
        ip_box[ip] = (yy, h)
    # edges: port order follows the other end's vertical position
    acc_port: dict = {}
    for a in pn["left"] + pn["right"]:
        x, yy, h = centers[a]
        ips = sorted(pn["acc_ips"][a], key=lambda ip: (ip_box[ip][0] + ip_box[ip][1] // 2, ip))
        for ip, py in zip(ips, _ports(yy + h // 2, len(ips))):
            acc_port[(a, ip)] = py
    ip_port: dict = {}
    for ip in pn["ips_ord"]:
        yy, h = ip_box[ip]
        for c in ("L", "R"):
            accs = sorted([a for a in pn["ip_accs"][ip] if side[a] == c], key=lambda a: (acc_port[(a, ip)], a))
            for a, py in zip(accs, _ports(yy + h // 2, len(accs))):
                ip_port[(a, ip)] = py
    cl = (v.get("closest_a"), v.get("closest_b"), v.get("closest_ip"))
    for e in sorted(pn["edges"], key=lambda e: (e["account"], e["ip"])):
        a, ip = e["account"], e["ip"]
        hot = ip == cl[2] and a in (cl[0], cl[1]) and pn["closest_ip"] == ip
        col = ACCENT if hot else INK
        ay, iy = acc_port[(a, ip)], ip_port[(a, ip)]
        lab = fmt_n(e["events"])
        pw = max(24, int(-(-(text_width(lab, "mono") + 8) // 8)) * 8)
        first = e["first_id"] or dbm.one(ctx.con, "SELECT id FROM events WHERE ip = ? AND account = ? ORDER BY ts_epoch IS NULL, ts_epoch, id "
                                                  "LIMIT 1", (ip, a))
        cite = ctx.cite(first)
        tip = (f"{fid} · {a} used {ip} in {fmt_n(e['events'])} record{'s' if e['events'] != 1 else ''}, "
               f"{e['first_utc'] or '?'} to {e['last_utc'] or '?'} UTC" + (f"; first record {cite}" if cite else ""))
        if side[a] == "L":
            x_box = L_X + ACC_W
            s.line(x_box, ay, x_box + 8, ay, stroke=col, tip=tip)
            px = x_box + 8
            s.line(px + pw, ay, IP_X, iy, stroke=col, tip=tip)
        else:
            x_box = R_X
            px = x_box - 8 - pw
            s.line(px + pw, ay, x_box, ay, stroke=col, tip=tip)
            s.line(IP_X + IP_W, iy, px, ay, stroke=col, tip=tip)
        s.pill(px, ay - 8, lab, fill=PAPER, stroke=col, color=col, tip=tip, min_w=pw,
               attrs={"class": "cite", "data-cite": cite} if cite else None)
        if hot and closest_cite is None:
            closest_cite = cite
    fig.refs.append(Ref(f"panel {pn['k']}", fid, f"{len(pn['acc'])} accounts and {len(pn['ips'])} shared IPs; line labels are each "
                        "account's records on that IP" + (f"; closest co-use on {v.get('closest_ip')} ({v.get('closest')})" if v.get("closest_ip") else ""),
                        cite=closest_cite))
    accs_sql = ", ".join("'" + a.replace("'", "''") + "'" for a in pn["acc"])
    ips_sql = ", ".join("'" + ip + "'" for ip in pn["ips"])
    fig.data_sql.append((f"panel {pn['k']} ({fid}) lines and labels",
                         f"SELECT account, ip, events AS records, first_utc, last_utc FROM ip_accounts WHERE ip IN ({ips_sql}) "
                         f"AND account IN ({accs_sql}) ORDER BY account, ip"))
