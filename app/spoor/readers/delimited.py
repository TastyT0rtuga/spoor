"""CSV / TSV / pipe / semicolon files and plain text (logs, mbox, .txt returns).

Tracks the physical line number and byte offset of every record so each citation points at
an exact place in the original file, and a long ingest can resume from a checkpoint."""
from __future__ import annotations

import csv
import sys
from typing import Iterator, Optional

from ..ipaddr import split_ip_port
from ..timeparse import looks_like_timestamp
from ..util import detect_encoding
from .textmode import Rec, TextModeExtractor, single_line_record

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
DELIMS = [",", "\t", "|", ";"]
DELIM_NAMES = {",": "comma", "\t": "tab", "|": "pipe", ";": "semicolon"}


def _decode(b: bytes, enc: str, first: bool) -> str:
    if enc in ("utf-8", "utf-8-sig"):
        s = b.decode("utf-8", errors="replace")
        return s.lstrip("﻿") if first else s
    return b.decode(enc, errors="replace")


def read_head_lines(path, enc: Optional[str] = None, max_bytes: int = 512 * 1024, max_lines: int = 400):
    with open(path, "rb") as f:
        head = f.read(max_bytes)
    enc = enc or detect_encoding(head)
    if enc.startswith("utf-16"):
        text = head.decode(enc, errors="replace")
        lines = text.splitlines(keepends=True)[:max_lines]
        return enc, lines
    lines = []
    # split on \n only, as the record reader does: a bare \r inside a quoted cell is not a line break
    # (files that use \r alone as the line ending are split on it as before)
    parts = head.split(b"\n") if b"\n" in head else head.splitlines(keepends=True)
    if b"\n" in head:
        parts = [x + b"\n" for x in parts[:-1]] + ([parts[-1]] if parts[-1] else [])
    for i, b in enumerate(parts):
        if i >= max_lines:
            break
        lines.append(_decode(b, enc, i == 0))
    if lines and len(head) == max_bytes and not head.endswith(b"\n"):
        lines = lines[:-1]  # last line is cut
    return enc, lines


def _count_fields(line: str, d: str) -> int:
    try:
        return len(next(csv.reader([line], delimiter=d)))
    except (csv.Error, StopIteration):
        return 0


def _is_headerish(cells: list[str]) -> bool:
    vals = [c.strip() for c in cells if c and c.strip()]
    if len(vals) < max(2, len(cells) * 0.5):
        return False
    bad = 0
    for v in vals:
        if split_ip_port(v) or looks_like_timestamp(v):
            bad += 1
        elif v.replace(".", "", 1).replace(",", "").lstrip("-").isdigit():
            bad += 1
    return bad <= len(vals) * 0.2


def sniff_table(lines: list[str]) -> Optional[dict]:
    """Find delimiter, header line and column count. None when the text is not a table."""
    body = [l for l in lines if l.strip()]
    if len(body) < 2:
        return None
    best = None
    idx = [i for i, l in enumerate(lines) if l.strip()]
    for d in DELIMS:
        if not any(d in l for l in body[:50]):
            continue
        counts = {i: _count_fields(lines[i], d) for i in idx}
        for start_pos, s in enumerate(idx[:60]):
            k = counts[s]
            if k < 2:
                continue
            rest = idx[start_pos:]
            if len(rest) < 2:
                continue
            match = sum(1 for i in rest if counts[i] == k) / len(rest)
            if match < 0.75:
                continue
            score = match * (min(k, 12) ** 0.5) * min(len(rest), 20)
            if best is None or score > best["score"] + 1e-9:
                best = {"score": score, "delimiter": d, "start": s, "ncols": k, "match": match}
            break  # the first consistent block for this delimiter wins
    if not best:
        return None
    first = next(csv.reader([lines[best["start"]]], delimiter=best["delimiter"]))
    header = _is_headerish(first)
    best["has_header"] = header
    best["header_line"] = best["start"] + 1 if header else None
    best["headers"] = _dedupe([c.strip() for c in first]) if header else [f"col{i + 1}" for i in range(best["ncols"])]
    best["data_start_line"] = best["start"] + (2 if header else 1)
    return best


def _dedupe(headers: list[str]) -> list[str]:
    out, seen = [], {}
    for i, h in enumerate(headers):
        h = h or f"col{i + 1}"
        if h in seen:
            seen[h] += 1
            h = f"{h}_{seen[h]}"
        else:
            seen[h] = 1
        out.append(h)
    return out


BLOCK_SCAN_BYTES = 64 * 1024 * 1024


def _nonempty(cells: list[str]) -> list[str]:
    return [c.strip() for c in cells if c and c.strip()]


def _strict_header(vals: list[str]) -> bool:
    for v in vals:
        if split_ip_port(v) or looks_like_timestamp(v):
            return False
        if v.replace(".", "", 1).replace(",", "").lstrip("-+").isdigit():
            return False
    return _is_headerish(vals)


def find_blocks(path, enc: str, d: str) -> list[dict]:
    """Header rows that each start a table of their own - a carrier report text file holding a voice table and
    a data table, or a tower-dump file with one section per search. A header row has 4+ named columns, is
    headerish, and the next non-empty line is a data row (at least half as many filled cells, not headerish).
    Free lines between tables are kept as that table's section labels. Returns [] unless there are 2+ headers,
    so ordinary single-table files are read exactly as before. Reads at most BLOCK_SCAN_BYTES."""
    if enc.startswith("utf-16"):
        return []
    heads: list[dict] = []
    labels: list[tuple[int, str]] = []
    pending = None            # a header candidate waiting for the next line
    seen_rows = False         # any table-like row seen yet
    prev_label = False        # the previous non-empty line was a label (one filled cell)
    read = 0
    with open(path, "rb") as f:
        for i, b in enumerate(f, 1):
            read += len(b)
            if read > BLOCK_SCAN_BYTES:
                break
            s_ = _decode(b, enc, i == 1).rstrip("\r\n")
            if not s_.strip():
                continue
            try:
                cells = next(csv.reader([s_], delimiter=d))
            except (csv.Error, StopIteration):
                cells = [s_]
            ne = _nonempty(cells)
            if pending is not None:
                if len(ne) >= max(2, len(pending["n"]) // 2) and not _is_headerish(ne):
                    heads.append({"line": pending["line"], "headers": pending["headers"], "labels": pending["labels"]})
                pending = None
            # a header row: 4+ named cells, none of them a number, date or IP; a table after the first one must
            # follow a label line ('Data Usage For: ...', 'Search Criteria ...') or repeat the first header -
            # so a data row that happens to look like words is never taken for a new table
            starts_ok = not seen_rows or prev_label or (heads and [c.strip() for c in cells][: len(heads[0]["headers"])]
                                                        == heads[0]["headers"])
            if len(ne) >= 4 and starts_ok and _strict_header(ne):
                hdr = [c.strip() for c in cells]
                last = max(k for k, c in enumerate(hdr) if c) + 1
                pending = {"line": i, "headers": hdr[:last], "n": ne, "labels": labels[-4:]}
                labels = []
                prev_label = False
            elif len(ne) <= 1:
                labels.append((i, s_.strip()))
                prev_label = True
            else:
                labels = []
                seen_rows = True
                prev_label = False
    return heads if len(heads) >= 2 else []


def _block_name(labels: list[tuple[int, str]], k: int, used: set) -> str:
    import re as _re
    base = ""
    for _ln, t in reversed(labels):           # the label nearest the header names the table
        t = _re.sub(r"\s+", " ", t).strip(" -:")
        if t and len(t) <= 80 and not t.lower().startswith(("date range", "page ")):
            base = t
            break
    base = base or f"table {k + 1}"
    name, n = base, 1
    while name in used:
        n += 1
        name = f"{base} ({n})"
    used.add(name)
    return name


def _scan_blocks(path, name: str, enc: str, d: str, blocks: list[dict], lines: list[str], out: dict) -> dict:
    out["kind"] = "delimited"
    used: set = set()
    tables = []
    for k, b in enumerate(blocks):
        nxt = blocks[k + 1] if k + 1 < len(blocks) else None
        end = (nxt["labels"][0][0] if nxt and nxt["labels"] else nxt["line"]) if nxt else None
        headers = _dedupe(b["headers"])
        tables.append({"name": _block_name(b["labels"], k, used), "mode": "table", "delimiter": d,
                       "header_line": b["line"], "data_start_line": b["line"] + 1, "end_line": end,
                       "headers": headers, "ncols": len(headers), "samples": [], "header_cite": f"L{b['line']}",
                       "section": " | ".join(t for _l, t in b["labels"] if len(t) <= 100 and ":" in t)})
    # samples: up to 200 rows per table
    with open(path, "rb") as f:
        ti = 0
        for i, bl in enumerate(f, 1):
            while ti < len(tables) and tables[ti]["end_line"] is not None and i >= tables[ti]["end_line"]:
                ti += 1
            if ti >= len(tables):
                break
            t = tables[ti]
            if i < t["data_start_line"] or len(t["samples"]) >= 200:
                if all(len(x["samples"]) >= 200 for x in tables):
                    break
                continue
            s_ = _decode(bl, enc, i == 1).rstrip("\r\n")
            if not s_.strip():
                continue
            try:
                r = next(csv.reader([s_], delimiter=d))
            except csv.Error:
                continue
            if len(r) > t["ncols"] and not any(c.strip() for c in r[t["ncols"]:]):
                r = r[: t["ncols"]]
            if len(r) == t["ncols"]:
                t["samples"].append(r)
    first = blocks[0]["line"]
    pre = [(f"L{i + 1}", lines[i].strip()) for i in range(min(first - 1, 60)) if i < len(lines) and lines[i].strip()]
    for b in blocks[1:]:
        pre += [(f"L{ln}", t) for ln, t in b["labels"]]
    out["preamble"] = pre
    out["tables"] = tables
    out["notes"].append(f"{DELIM_NAMES[d]}-delimited, {len(tables)} tables in one file: "
                        + "; ".join(f"'{t['name']}' ({t['ncols']} columns, header at line {t['header_line']})" for t in tables))
    return out


def scan(path, name: str) -> dict:
    enc, lines = read_head_lines(path)
    t = sniff_table(lines)
    out = {"kind": "text", "encoding": enc, "tables": [], "preamble": [], "notes": []}
    order = ([t["delimiter"]] if t else []) + [x for x in DELIMS if not t or x != t["delimiter"]]
    for d in order:
        if sum(1 for l in lines[:400] if d in l) >= 3:
            blocks = find_blocks(path, enc, d)
            if blocks:
                return _scan_blocks(path, name, enc, d, blocks, lines, out)
    if t:
        hl = t["header_line"] or t["data_start_line"]
        pre_end = (t["header_line"] or t["data_start_line"]) - 1
        out["preamble"] = [(f"L{i + 1}", lines[i].strip()) for i in range(min(pre_end, 60)) if lines[i].strip()]
        rows = []
        for ln in lines[t["data_start_line"] - 1:]:
            if not ln.strip():
                continue
            try:
                r = next(csv.reader([ln], delimiter=t["delimiter"]))
            except csv.Error:
                continue
            if len(r) == t["ncols"]:
                rows.append(r)
            if len(rows) >= 200:
                break
        out["kind"] = "delimited"
        out["tables"].append({
            "name": "main", "mode": "table", "delimiter": t["delimiter"], "header_line": t["header_line"],
            "data_start_line": t["data_start_line"], "headers": t["headers"], "ncols": t["ncols"],
            "samples": rows, "header_cite": f"L{hl}" if t["header_line"] else None,
        })
        out["notes"].append(f"{DELIM_NAMES[t['delimiter']]}-delimited, {t['ncols']} columns, "
                            + (f"header at line {t['header_line']}" if t["header_line"] else "no header row")
                            + (f", {pre_end} preamble line(s)" if pre_end else ""))
    else:
        out["preamble"] = [(f"L{i + 1}", l.strip()) for i, l in enumerate(lines[:30]) if l.strip()]
        ip_only = ts_only = both = 0
        from .textmode import analyse_line
        for i, l in enumerate(lines[:400]):
            a = analyse_line("", i, None, None, l)
            if a.ips and a.ts:
                both += 1
            elif a.ips:
                ip_only += 1
            elif a.ts:
                ts_only += 1
        pair = ip_only >= 3 and ts_only >= 3 and both < ip_only
        out["tables"].append({"name": "text", "mode": "text", "pair_window": 6 if pair else 0,
                              "samples": [[l.rstrip()] for l in lines[:20]], "headers": ["line"]})
        out["notes"].append("free text: lines with timestamps, IPs or identifiers become records"
                            + ("; IP and timestamp appear on separate lines - proximity pairing suggested" if pair else ""))
    return out


class _LineFeeder:
    """Feeds decoded lines to csv.reader while remembering where each record began and ended."""

    def __init__(self, f, enc: str, start_line: int, start_offset: int):
        self.f = f
        self.enc = enc
        self.line = start_line
        self.offset = start_offset
        self.rec_start_line = start_line + 1
        self.rec_start_offset = start_offset
        self.buf: list[str] = []

    def __iter__(self):
        return self

    def __next__(self) -> str:
        b = self.f.readline()
        if not b:
            raise StopIteration
        first = self.offset == 0
        self.line += 1
        self.offset += len(b)
        s = _decode(b, self.enc, first)
        self.buf.append(s)
        return s

    def take(self) -> tuple[int, int, int, int, str]:
        raw = "".join(self.buf)
        res = (self.rec_start_line, self.line, self.rec_start_offset, self.offset - self.rec_start_offset, raw)
        self.buf = []
        self.rec_start_line = self.line + 1
        self.rec_start_offset = self.offset
        return res


def iterate(path, cfg: dict, table: dict, resume: Optional[dict] = None) -> Iterator[tuple[Rec, dict]]:
    """Yield (record, checkpoint). checkpoint = {'line','offset','rows'} after this record."""
    enc = cfg.get("encoding") or "utf-8"
    if enc.startswith("utf-16"):
        yield from _iterate_utf16(path, cfg, table, resume)
        return
    rows = (resume or {}).get("rows", 0)
    with open(path, "rb") as f:
        line0 = (resume or {}).get("line", 0)
        off0 = (resume or {}).get("offset", 0)
        f.seek(off0)
        if table.get("mode") == "text":
            yield from _iterate_text(f, enc, table, line0, off0, rows)
            return
        d = table["delimiter"]
        ncols = table["ncols"]
        headers = table["headers"]
        data_start = table["data_start_line"]
        feeder = _LineFeeder(f, enc, line0, off0)
        if line0 < data_start - 1:
            # skip preamble/header without treating them as records
            while feeder.line < data_start - 1:
                try:
                    next(feeder)
                except StopIteration:
                    return
            feeder.take()
        reader = csv.reader(feeder, delimiter=d)
        end_line = table.get("end_line")
        hdr_cmp = [h.strip() for h in table.get("headers") or []] if table.get("header_line") else None
        while True:
            if end_line is not None and feeder.line + 1 >= end_line:
                break
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error:
                row = None
            l1, l2, off, ln, raw = feeder.take()
            loc = f"L{l1}" if l1 == l2 else f"L{l1}-{l2}"
            raw_s = raw.rstrip("\r\n")
            if row is not None and len(row) == 0 or not raw_s.strip():
                continue
            if hdr_cmp and row is not None and [c.strip() for c in row[: len(hdr_cmp)]] == hdr_cmp:
                continue          # the header repeated inside the data (paged exports): not a record
            ck = {"line": l2, "offset": off + ln, "rows": rows + 1}
            if row is not None and len(row) != ncols and len(row) > ncols and not any(c.strip() for c in row[ncols:]):
                row = row[:ncols]
            if row is not None and len(row) == ncols:
                rows += 1
                yield Rec(loc, l1, off, ln, raw_s, dict(zip(headers, row)), table.get("name")), ck
            else:
                rec = single_line_record(loc, l1, off, ln, raw_s, table.get("name"),
                                         note="line does not match the table layout; read as free text")
                rows += 1
                if rec is None:
                    rec = Rec(loc, l1, off, ln, raw_s, None, table.get("name"), {},
                              "line does not match the table layout and holds no timestamp/IP/identifier")
                    rec.extra = {"skip": True}
                yield rec, ck


def _iterate_text(f, enc, table, line0, off0, rows) -> Iterator[tuple[Rec, dict]]:
    window = int(table.get("pair_window") or 0)
    ex = TextModeExtractor(window=window or 1, table=table.get("name"))
    line, off = line0, off0
    first = off0 == 0
    for b in iter(f.readline, b""):
        line += 1
        s = _decode(b, enc, first and line == 1).rstrip("\r\n")
        if window:
            for r in ex.feed(f"L{line}", line, off, len(b), s):
                rows += 1
                yield r, None
        else:
            r = single_line_record(f"L{line}", line, off, len(b), s, table.get("name")) if s.strip() else None
            if r is not None:
                rows += 1
                yield r, {"line": line, "offset": off + len(b), "rows": rows}
        off += len(b)
    for r in ex.finish():
        rows += 1
        yield r, None


def _iterate_utf16(path, cfg, table, resume) -> Iterator[tuple[Rec, dict]]:
    """UTF-16 files: line numbers are exact; byte offsets are not tracked (resume restarts the file)."""
    enc = cfg.get("encoding")
    with open(path, "r", encoding=enc, errors="replace", newline="") as fh:
        text_lines = (l for l in fh)
        if table.get("mode") == "text":
            line = 0
            for s in text_lines:
                line += 1
                r = single_line_record(f"L{line}", line, None, None, s.rstrip("\r\n"), table.get("name"))
                if r is not None:
                    yield r, None
            return
        d, ncols, headers, data_start = table["delimiter"], table["ncols"], table["headers"], table["data_start_line"]
        line = 0
        for s in text_lines:
            line += 1
            if line < data_start:
                continue
            raw = s.rstrip("\r\n")
            if not raw.strip():
                continue
            try:
                row = next(csv.reader([raw], delimiter=d))
            except csv.Error:
                row = None
            if row is not None and len(row) == ncols:
                yield Rec(f"L{line}", line, None, None, raw, dict(zip(headers, row)), table.get("name")), None
            else:
                r = single_line_record(f"L{line}", line, None, None, raw, table.get("name"),
                                       note="line does not match the table layout; read as free text")
                if r is not None:
                    yield r, None


def read_lines_at(path, enc: str, items: list[tuple[int, Optional[int], Optional[int]]]) -> dict[int, str]:
    """Re-read specific physical lines (line_no, offset, length) straight from disk for citation checks."""
    out: dict[int, str] = {}
    if enc.startswith("utf-16") or any(o is None for _, o, _ in items):
        want = {l for l, _, _ in items}
        with open(path, "r", encoding=enc if enc.startswith("utf-16") else ("utf-8" if enc == "utf-8-sig" else enc),
                  errors="replace", newline="") as fh:
            for i, s in enumerate(fh, 1):
                if i in want:
                    out[i] = s.lstrip("﻿") if i == 1 else s
                    if len(out) == len(want):
                        break
        return out
    with open(path, "rb") as f:
        for line, off, ln in items:
            f.seek(off)
            b = f.read(ln) if ln else f.readline()
            out[line] = _decode(b, enc, off == 0)
    return out
