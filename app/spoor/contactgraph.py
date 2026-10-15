"""Contact paths between phone numbers ("degrees of separation") across any number of telecom returns.

The graph is built only from records:
  contact   two numbers in the same call/text record (call-detail returns and calls seen in tower dumps). A hop is
            only visible where at least one end is a number whose records were returned, so a chain alternates
            between returned numbers (targets, dump phones) and their contacts.
  dump      (optional) a tower dump (one dump file/section) joined to every phone on it. Dump nodes are endpoints only:
            a path never runs THROUGH a dump unless the dump itself was chosen.
  handset   (optional) an IMEI joined to every number that used it (same physical phone under several numbers).

Numbers that would join unrelated people are not used as stepping stones (they can still be chosen as endpoints):
short codes and service numbers (fewer than 7 digits, e.g. 611), and contact numbers with more than `tel_hub_max`
different neighbours (voicemail platforms, businesses). Every one left out is listed with the result.

For the chosen numbers (2 or more) every pair is searched breadth-first up to `max_hops`; the result is the set of
shortest chains for each pair (plus chains up to `slack` hops longer, if asked), each hop with its record count,
first/last time, the returns it is in and the citations of its first and last record. Deterministic: the same records
and the same choice give the same chains in the same order. Nothing is inferred: a chain says these numbers were in
contact one after another in the records; it does not say information passed along it."""
from __future__ import annotations

import collections
import itertools
import re

from . import db as dbm

DIG = re.compile(r"\D")


def digits(n: str) -> int:
    return len(DIG.sub("", n or ""))


def node_label(n: str) -> str:
    if n.startswith("dump:"):
        return "tower dump " + n[5:]
    if n.startswith("imei:"):
        return "handset IMEI " + n[5:]
    return n


class Graph:
    def __init__(self, con, params: dict | None = None, dumps: bool = True, devices: bool = False):
        p = params or {}
        self.con = con
        self.hub_max = int(p.get("tel_hub_max", 25))
        self.adj: dict = collections.defaultdict(set)
        self.edges: dict = {}
        self.returned: set = set()        # numbers whose own records are in the case (targets, dump phones)
        self.targets: list = []
        self.dumps: dict = {}             # node -> {"label", "records", "phones"}
        self.kind: dict = {}
        self._build(dumps, devices)

    # ------------------------------------------------------------------ build
    def _edge(self, a, b, via, r):
        if a == b:
            return
        k = (a, b) if a < b else (b, a)
        e = self.edges.get(k)
        if e is None:
            e = self.edges[k] = {"a": k[0], "b": k[1], "n": 0, "calls": 0, "texts": 0, "first": None, "last": None, "first_ts": None,
                                 "last_ts": None, "first_id": None, "last_id": None, "returns": set(), "via": set()}
            self.adj[k[0]].add(k[1])
            self.adj[k[1]].add(k[0])
        e["n"] += 1
        e["via"].add(via)
        if r.get("kind") == "voice":
            e["calls"] += 1
        elif r.get("kind") in ("sms", "mms", "rcs"):
            e["texts"] += 1
        if r.get("ret"):
            e["returns"].add(r["ret"])
        key = (r["ts_epoch"] if r["ts_epoch"] is not None else float("inf"), r["event_id"])
        if e["first_ts"] is None or key < e["first_ts"]:
            e["first_ts"], e["first"], e["first_id"] = key, r["ts_utc"], r["event_id"]
        if e["last_ts"] is None or key > e["last_ts"]:
            e["last_ts"], e["last"], e["last_id"] = key, r["ts_utc"], r["event_id"]

    def _build(self, dumps: bool, devices: bool):
        con = self.con
        rows = dbm.rows(con, "SELECT t.event_id, t.target, t.other, t.kind, t.ts_epoch, t.ts_utc, t.imei, COALESCE(t.src_kind,'cdr') AS sk, "
                             "t.source_id, COALESCE(t.section,'') AS section, s.label AS slabel, s.display, r.label AS ret "
                             "FROM tel t JOIN sources s ON s.id=t.source_id LEFT JOIN returns r ON r.id=s.return_id "
                             "WHERE t.target IS NOT NULL AND COALESCE(t.dir,'') != 'fwd' ORDER BY t.ts_epoch IS NULL, t.ts_epoch, t.event_id")
        tcount = collections.Counter()
        for r in rows:
            self.returned.add(r["target"])
            if r["sk"] != "dump":
                tcount[r["target"]] += 1
                self.kind.setdefault(r["target"], "target")
            else:
                self.kind.setdefault(r["target"], "dump phone")
            if r["other"]:
                self.kind.setdefault(r["other"], "contact")
                self._edge(r["target"], r["other"], "dump" if r["sk"] == "dump" else "cdr", r)
            if r["sk"] == "dump" and dumps:
                fn = (r["display"] or "").replace("\\", "/").split("/")[-1]
                dn = f"dump:{r['slabel']}" + (f"/{r['section'][:40]}" if r["section"] else "")
                d = self.dumps.setdefault(dn, {"label": f"{r['slabel']} {fn}" + (f" ({r['section'][:60]})" if r["section"] else ""),
                                              "records": 0, "phones": set(), "ret": r["ret"]})
                d["records"] += 1
                d["phones"].add(r["target"])
                self.kind[dn] = "dump"
                self._edge(dn, r["target"], "on dump", r)
            if devices and r["imei"]:
                self.kind.setdefault("imei:" + r["imei"], "handset")
                self._edge("imei:" + r["imei"], r["target"], "handset", r)
        if devices:          # an IMEI used by one number only adds nothing
            for n in [n for n, k in self.kind.items() if k == "handset" and len(self.adj[n]) < 2]:
                for m in list(self.adj[n]):
                    self.adj[m].discard(n)
                    self.edges.pop((n, m) if n < m else (m, n), None)
                self.adj.pop(n, None)
                self.kind.pop(n, None)
        self.targets = [t for t, _n in sorted(tcount.items(), key=lambda kv: (-kv[1], kv[0]))]

    # ------------------------------------------------------------------ rules
    def blocked_reason(self, n: str) -> str | None:
        if n.startswith("dump:"):
            return "tower dump (endpoint only)"
        if n.startswith("imei:"):
            return None
        if digits(n) < 7:
            return "short code / service number"
        if n not in self.returned and len(self.adj[n]) > self.hub_max:
            return f"in contact with {len(self.adj[n])} different numbers (more than {self.hub_max})"
        return None

    def find(self, q: str) -> str | None:
        """Resolve what the analyst typed (any formatting, with or without +1) to a node."""
        q = (q or "").strip()
        if q in self.kind:
            return q
        if q.lower().startswith("dump:"):          # dump:S08, or dump:<part of the dump's file name>
            k = q[5:].strip().lower()
            hits = sorted(n for n, d in self.dumps.items() if n.lower() == q.lower() or (k and k in d["label"].lower()))
            return hits[0] if hits else None
        if q.lower().startswith("imei:"):
            return q if q in self.kind else None
        d = DIG.sub("", q)
        if not d:
            return None
        cands = [n for n in self.kind if not n.startswith(("dump:", "imei:")) and (DIG.sub("", n) == d or DIG.sub("", n)[-10:] == d[-10:] and len(d) >= 10)]
        return sorted(cands)[0] if cands else None

    # ------------------------------------------------------------------ search
    def _bfs(self, s: str, seeds: set, limit: int) -> dict:
        dist = {s: 0}
        q = collections.deque([s])
        while q:
            u = q.popleft()
            if dist[u] >= limit:
                continue
            if u != s and u not in seeds and self.blocked_reason(u):
                continue          # reached, but not a stepping stone
            for v in sorted(self.adj[u]):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    q.append(v)
        return dist

    def connect(self, seeds: list, max_hops: int = 6, slack: int = 0, max_paths: int = 25) -> dict:
        seeds = list(dict.fromkeys(seeds))
        sset = set(seeds)
        dist = {s: self._bfs(s, sset, max_hops + slack) for s in seeds}
        pairs, used_nodes, used_edges, through = [], set(seeds), set(), collections.defaultdict(lambda: {"pairs": set(), "paths": 0})
        blocked_seen = set()
        for a, b in itertools.combinations(seeds, 2):
            da, db = dist[a], dist[b]
            d = da.get(b)
            if d is None or d > max_hops:
                pairs.append({"a": a, "b": b, "hops": None, "paths": [], "more": False})
                continue
            limit = d + slack
            paths: list = []
            more = False

            def walk(u, path, seen):
                nonlocal more
                if len(paths) >= max_paths:
                    more = True
                    return
                if u == b:
                    paths.append(list(path))
                    return
                if len(path) - 1 >= limit:
                    return
                if u != a and u not in sset and self.blocked_reason(u):
                    blocked_seen.add(u)
                    return
                for v in sorted(self.adj[u]):
                    if v in seen:
                        continue
                    hv = len(path)            # hops to v if taken
                    if v not in db or hv + db[v] > limit:
                        continue
                    seen.add(v)
                    path.append(v)
                    walk(v, path, seen)
                    path.pop()
                    seen.discard(v)
            walk(a, [a], {a})
            paths.sort(key=lambda p: (len(p), -min(self.edges[self._k(x, y)]["n"] for x, y in zip(p, p[1:])), p))
            for p in paths:
                used_nodes.update(p)
                for x, y in zip(p, p[1:]):
                    used_edges.add(self._k(x, y))
                for m in p[1:-1]:
                    through[m]["pairs"].add((a, b))
                    through[m]["paths"] += 1
            pairs.append({"a": a, "b": b, "hops": d, "paths": paths, "more": more})
        hubs = sorted({n for s in seeds for n in dist[s] if n not in sset and self.blocked_reason(n)} | blocked_seen,
                      key=lambda n: (-len(self.adj[n]), n))
        return {"seeds": seeds, "max_hops": max_hops, "slack": slack, "pairs": pairs, "nodes": sorted(used_nodes), "edges": sorted(used_edges),
                "through": {n: {"pairs": sorted(v["pairs"]), "paths": v["paths"]} for n, v in through.items()},
                "left_out": [{"node": n, "reason": self.blocked_reason(n)} for n in hubs]}

    @staticmethod
    def _k(x, y):
        return (x, y) if x < y else (y, x)

    # ------------------------------------------------------------------ output
    def cites(self, ids) -> dict:
        ids = [i for i in ids if i is not None]
        if not ids:
            return {}
        ph = ",".join("?" * len(ids))
        return {r[0]: r[1] for r in self.con.execute(f"SELECT e.id, s.label || ':' || e.loc FROM events e JOIN sources s ON s.id=e.source_id WHERE e.id IN ({ph})", ids)}

    def edge_json(self, k, cites: dict) -> dict:
        e = self.edges[k]
        return {"a": e["a"], "b": e["b"], "records": e["n"], "calls": e["calls"], "texts": e["texts"], "first_utc": e["first"], "last_utc": e["last"],
                "returns": sorted(e["returns"]), "via": sorted(e["via"]), "first_cite": cites.get(e["first_id"]), "last_cite": cites.get(e["last_id"]),
                "first_id": e["first_id"], "last_id": e["last_id"]}

    def node_json(self, n: str, seeds: set) -> dict:
        d = self.dumps.get(n)
        return {"id": n, "label": d["label"] if d else n, "kind": self.kind.get(n, "contact"), "chosen": n in seeds,
                "returned": n in self.returned, "degree": len(self.adj[n]), **({"records": d["records"], "phones": len(d["phones"])} if d else {})}

    def result_json(self, res: dict) -> dict:
        ids = [x for k in res["edges"] for x in (self.edges[k]["first_id"], self.edges[k]["last_id"])]
        c = self.cites(ids)
        sset = set(res["seeds"])
        return {**res, "nodes": [self.node_json(n, sset) for n in res["nodes"]], "edges": [self.edge_json(k, c) for k in res["edges"]],
                "through": [{"node": n, **v, "pairs": [list(p) for p in v["pairs"]]} for n, v in
                            sorted(res["through"].items(), key=lambda kv: (-len(kv[1]["pairs"]), -kv[1]["paths"], kv[0]))]}

    def choices(self) -> dict:
        """What the analyst can pick: targets, dumps, and how many other numbers exist."""
        return {"targets": [{"id": t, "records": sum(self.edges[self._k(t, o)]["n"] for o in self.adj[t] if not o.startswith(("dump:", "imei:"))),
                             "contacts": sum(1 for o in self.adj[t] if not o.startswith(("dump:", "imei:")))} for t in self.targets],
                "dumps": [{"id": n, "label": d["label"], "records": d["records"], "phones": len(d["phones"]), "ret": d["ret"]}
                          for n, d in sorted(self.dumps.items())],
                "numbers": sum(1 for n in self.kind if not n.startswith(("dump:", "imei:"))), "hub_max": self.hub_max}


def path_text(g: Graph, p: list, cites: dict | None = None) -> str:
    """'A -[3 records, R02, S03:L12..S03:L40]- B -...- C'"""
    out = [node_label(p[0])]
    for x, y in zip(p, p[1:]):
        e = g.edges[g._k(x, y)]
        c = cites or {}
        bits = [f"{e['n']} record{'s' if e['n'] != 1 else ''}"]
        if e["returns"]:
            bits.append(",".join(sorted(e["returns"])))
        if c.get(e["first_id"]):
            bits.append(c[e["first_id"]] + (f"..{c[e['last_id']]}" if e["last_id"] != e["first_id"] and c.get(e["last_id"]) else ""))
        out.append(f" -[{'; '.join(bits)}]- {node_label(y)}")
    return "".join(out)
