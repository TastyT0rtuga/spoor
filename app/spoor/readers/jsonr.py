"""JSON documents, JSON Lines and very large top-level JSON arrays (streamed).

Citations: '$.path[index]' for documents (any JSON viewer can follow it), 'L<line>' for JSON Lines."""
from __future__ import annotations

import json
import os
import re
from typing import Any, Iterator, Optional

from ..util import detect_encoding
from .textmode import Rec, single_line_record

BIG_JSON = 512 * 1024 * 1024
_KEY_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def flatten(obj: dict, prefix: str = "", out: Optional[dict] = None, depth: int = 0) -> dict:
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and depth < 6:
            flatten(v, key, out, depth + 1)
        elif isinstance(v, list):
            if all(not isinstance(x, (dict, list)) for x in v):
                out[key] = "; ".join(_s(x) for x in v)
            else:
                out[key] = json.dumps(v, ensure_ascii=False)[:4000]
        else:
            out[key] = v
    return out


def _child(path: str, key) -> str:
    if isinstance(key, int):
        return f"{path}[{key}]"
    return f"{path}.{key}" if _KEY_OK.match(str(key)) else f'{path}["{key}"]'


def find_tables(obj, path: str = "$", depth: int = 0, out: Optional[list] = None) -> list[str]:
    out = [] if out is None else out
    if depth > 8:
        return out
    if isinstance(obj, list):
        dicts = [x for x in obj if isinstance(x, dict)]
        if dicts and len(dicts) >= 0.5 * len(obj):
            out.append(path)
            for it in dicts[:3]:
                for k, v in it.items():
                    if isinstance(v, (list, dict)):
                        find_tables(v, _child(path + "[*]", k), depth + 1, out)
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (list, dict)):
                find_tables(v, _child(path, k), depth + 1, out)
    return list(dict.fromkeys(out))


_TOK = re.compile(r'\.([A-Za-z_][A-Za-z0-9_]*)|\["((?:[^"\\]|\\.)*)"\]|\[(\*|\d+)\]')


def resolve(obj, path: str, concrete: str = "$") -> Iterator[tuple[str, Any]]:
    """Yield (concrete_path, value) for a path that may contain [*]."""
    toks = [m.groups() for m in _TOK.finditer(path[1:])]

    def walk(o, i, cp):
        if i == len(toks):
            yield cp, o
            return
        name, qname, idx = toks[i]
        if idx == "*":
            if isinstance(o, list):
                for j, it in enumerate(o):
                    yield from walk(it, i + 1, f"{cp}[{j}]")
        elif idx is not None:
            if isinstance(o, list) and int(idx) < len(o):
                yield from walk(o[int(idx)], i + 1, f"{cp}[{idx}]")
        else:
            k = name if name is not None else qname
            if isinstance(o, dict) and k in o:
                yield from walk(o[k], i + 1, _child(cp, k))

    yield from walk(obj, 0, concrete)


def _leaves(obj, path="$", tables=(), out=None, depth=0):
    out = [] if out is None else out
    if depth > 10 or len(out) > 20000:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            _leaves(v, _child(path, k), tables, out, depth + 1)
    elif isinstance(obj, list):
        if path in tables:
            return out
        for i, v in enumerate(obj):
            _leaves(v, _child(path, i), tables, out, depth + 1)
    else:
        out.append((path, f"{path.rsplit('.', 1)[-1]}: {_s(obj)}"))
    return out


def _sniff(path) -> tuple[str, str]:
    with open(path, "rb") as f:
        head = f.read(256 * 1024)
    enc = detect_encoding(head)
    text = head.decode("utf-8" if enc == "utf-8-sig" else enc, errors="replace").lstrip("﻿")
    lines = [l for l in text.splitlines() if l.strip()][:20]
    if len(lines) >= 2:
        ok = 0
        for l in lines[:-1]:
            try:
                if isinstance(json.loads(l), dict):
                    ok += 1
            except ValueError:
                pass
        if ok >= max(1, len(lines[:-1]) * 0.8):
            return "jsonl", enc
    return "json", enc


def _headers(rows: list[dict]) -> list[str]:
    seen: dict[str, None] = {}
    for r in rows:
        for k in r:
            seen.setdefault(k, None)
    return list(seen)


def scan(path, name: str) -> dict:
    kind, enc = _sniff(path)
    out = {"kind": kind, "encoding": enc, "tables": [], "preamble": [], "notes": []}
    if kind == "jsonl":
        rows = []
        with open(path, "r", encoding="utf-8" if enc == "utf-8-sig" else enc, errors="replace") as f:
            for i, l in enumerate(f):
                if i > 400:
                    break
                try:
                    o = json.loads(l)
                except ValueError:
                    continue
                if isinstance(o, dict):
                    rows.append(flatten(o))
        hd = _headers(rows)
        out["tables"].append({"name": "lines", "mode": "table", "headers": hd, "ncols": len(hd),
                              "samples": [[_s(r.get(h)) for h in hd] for r in rows[:200]],
                              "raw_samples": [[r.get(h) for h in hd] for r in rows[:200]]})
        out["notes"].append(f"JSON Lines, {len(hd)} keys")
        return out
    size = os.path.getsize(path)
    if size > BIG_JSON:
        with open(path, "rb") as f:
            c = f.read(4096).lstrip(b"\xef\xbb\xbf \r\n\t")
        if c.startswith(b"["):
            rows = []
            for _p, o in _stream_array(path, enc, limit=300):
                if isinstance(o, dict):
                    rows.append(flatten(o))
            hd = _headers(rows)
            out["tables"].append({"name": "$", "mode": "table", "stream": True, "headers": hd, "ncols": len(hd),
                                  "samples": [[_s(r.get(h)) for h in hd] for r in rows[:200]],
                                  "raw_samples": [[r.get(h) for h in hd] for r in rows[:200]]})
            out["notes"].append(f"large JSON array ({size / 1e9:.1f} GB) - streamed")
        else:
            out["kind"] = "text"
            out["tables"].append({"name": "text", "mode": "text", "pair_window": 0, "headers": ["line"], "samples": []})
            out["notes"].append("JSON document too large to load; read line by line as text")
        return out
    with open(path, "r", encoding="utf-8" if enc in ("utf-8", "utf-8-sig") else enc, errors="replace") as f:
        doc = json.load(f)
    tables = find_tables(doc)
    for t in tables:
        rows = []
        for _cp, v in resolve(doc, t):
            if isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        rows.append(flatten(it))
                    if len(rows) >= 300:
                        break
            if len(rows) >= 300:
                break
        hd = _headers(rows)
        est = sum(len(v) for _cp, v in resolve(doc, t) if isinstance(v, list))
        out["tables"].append({"name": t, "mode": "table", "headers": hd, "ncols": len(hd), "rows_estimate": est,
                              "samples": [[_s(r.get(h)) for h in hd] for r in rows[:200]],
                              "raw_samples": [[r.get(h) for h in hd] for r in rows[:200]]})
    leaves = _leaves(doc, tables=set(t for t in tables if "[*]" not in t))
    if leaves:
        out["tables"].append({"name": "values", "mode": "text", "pair_window": 0, "headers": ["value"],
                              "samples": [[l[1]] for l in leaves[:20]]})
        out["preamble"] = [(p, t) for p, t in leaves[:60]]
    out["notes"].append(f"JSON document: {len(tables)} record array(s)" + (f", {len(leaves)} other values" if leaves else ""))
    return out


def _stream_array(path, enc, limit: Optional[int] = None) -> Iterator[tuple[str, Any]]:
    dec = json.JSONDecoder()
    with open(path, "r", encoding="utf-8" if enc in ("utf-8", "utf-8-sig") else enc, errors="replace") as f:
        buf = f.read(1 << 20).lstrip("﻿").lstrip()
        if not buf.startswith("["):
            return
        buf = buf[1:]
        i = n = 0
        while True:
            while True:
                buf = buf.lstrip()
                if buf.startswith(","):
                    buf = buf[1:]
                    continue
                break
            if buf.startswith("]"):
                return
            try:
                obj, end = dec.raw_decode(buf)
            except ValueError:
                more = f.read(1 << 20)
                if not more:
                    return
                buf += more
                continue
            yield f"$[{i}]", obj
            i += 1
            n += 1
            buf = buf[end:]
            if limit and n >= limit:
                return
            if len(buf) < 65536:
                buf += f.read(1 << 20)


def iterate(path, cfg: dict, table: dict, resume: Optional[dict] = None) -> Iterator[tuple[Rec, dict]]:
    skip = (resume or {}).get("rows", 0)
    enc = cfg.get("encoding") or "utf-8"
    kind = cfg.get("kind")
    hd = table.get("headers") or []
    rows = 0
    if kind == "jsonl":
        line0 = (resume or {}).get("line", 0)
        off = (resume or {}).get("offset", 0)
        rows = skip
        with open(path, "rb") as f:
            f.seek(off)
            line = line0
            for b in iter(f.readline, b""):
                line += 1
                s = b.decode("utf-8" if enc in ("utf-8", "utf-8-sig") else enc, errors="replace")
                if off == 0 and line == 1:
                    s = s.lstrip("﻿")
                raw = s.rstrip("\r\n")
                ck_off = off + len(b)
                if raw.strip():
                    try:
                        o = json.loads(raw)
                    except ValueError:
                        o = None
                    rows += 1
                    if isinstance(o, dict):
                        cells = flatten(o)
                        yield Rec(f"L{line}", line, off, len(b), raw, cells, "lines"), {"line": line, "offset": ck_off, "rows": rows}
                    else:
                        r = single_line_record(f"L{line}", line, off, len(b), raw, "lines", note="line is not a JSON object; read as text")
                        if r is not None:
                            yield r, {"line": line, "offset": ck_off, "rows": rows}
                off = ck_off
        return
    if table.get("stream"):
        for cp, o in _stream_array(path, enc):
            rows += 1
            if rows <= skip:
                continue
            raw = json.dumps(o, ensure_ascii=False)
            cells = flatten(o) if isinstance(o, dict) else {"value": o}
            yield Rec(cp, None, None, None, raw, cells, "$"), {"rows": rows}
        return
    if kind == "text":
        from .delimited import iterate as it_text
        yield from it_text(path, {"encoding": enc}, {"mode": "text", "name": "text", "pair_window": 0}, resume)
        return
    with open(path, "r", encoding="utf-8" if enc in ("utf-8", "utf-8-sig") else enc, errors="replace") as f:
        doc = json.load(f)
    if table.get("mode") == "text":
        tables = set(t["name"] for t in cfg.get("tables", []) if t.get("mode") == "table" and "[*]" not in t["name"])
        for p, txt in _leaves(doc, tables=tables):
            rows += 1
            if rows <= skip:
                continue
            r = single_line_record(p, None, None, None, txt, "values")
            if r is not None:
                yield r, {"rows": rows}
        return
    for cp, v in resolve(doc, table["name"]):
        if not isinstance(v, list):
            continue
        for i, it in enumerate(v):
            if not isinstance(it, dict):
                continue
            rows += 1
            if rows <= skip:
                continue
            raw = json.dumps(it, ensure_ascii=False)
            cells = flatten(it)
            yield Rec(f"{cp}[{i}]", None, None, None, raw, {h: cells.get(h) for h in hd} | {k: cells[k] for k in cells if k not in hd},
                      table["name"]), {"rows": rows}
