"""PDF returns: text is extracted page by page (pypdf, layout mode) and read as free text.

Citations: p<page>:L<line> (line within the page's extracted text). Pages with no extractable
text (scanned images) are listed in the data-quality findings - nothing is skipped silently."""
from __future__ import annotations

from typing import Iterator, Optional

from .textmode import Rec, TextModeExtractor, single_line_record


def _reader(path):
    from pypdf import PdfReader
    r = PdfReader(path)
    if r.is_encrypted:
        try:
            r.decrypt("")
        except Exception:
            pass
    return r


def page_lines(page) -> list[str]:
    try:
        t = page.extract_text(extraction_mode="layout")
    except Exception:
        t = None
    if not t or not t.strip():
        try:
            t = page.extract_text()
        except Exception:
            t = ""
    return [l.rstrip() for l in (t or "").splitlines()]


def scan(path, name: str) -> dict:
    r = _reader(path)
    n = len(r.pages)
    out = {"kind": "pdf", "encoding": None, "tables": [], "preamble": [], "notes": [], "pages": n}
    samples, empty = [], []
    from .textmode import KEY_INLINE, analyse_line
    ip_only = ts_only = both = kv_ip = kv_ts = 0
    for i in range(min(n, 15)):
        lines = page_lines(r.pages[i])
        if not any(l.strip() for l in lines):
            empty.append(i + 1)
        for j, l in enumerate(lines):
            if l.strip() and len(out["preamble"]) < 60:
                out["preamble"].append((f"p{i + 1}:L{j + 1}", l.strip()))
            if l.strip() and len(samples) < 20:
                samples.append([l.strip()])
            a = analyse_line("", j, None, None, l)
            if a.ips and a.ts:
                both += 1
            elif a.ips:
                ip_only += 1
                kv_ip += bool(KEY_INLINE.match(l))
            elif a.ts:
                ts_only += 1
                kv_ts += bool(KEY_INLINE.match(l))
    pair = ip_only >= 3 and ts_only >= 3 and both < ip_only
    kv_pair = kv_ip >= 1 and kv_ts >= 1      # 'Time: ...' / 'IP Address: ...' records: pair inside each record
    out["tables"].append({"name": "text", "mode": "text", "pair_window": 6 if pair else (1 if kv_pair else 0), "headers": ["line"],
                          "samples": samples, "rows_estimate": n})
    out["notes"].append(f"PDF, {n:,} page(s); text read page by page"
                        + (f"; first pages without text: {empty[:10]}" if empty else "")
                        + ("; IP and timestamp on separate lines - proximity pairing suggested" if pair else ""))
    return out


def iterate(path, cfg: dict, table: dict, resume: Optional[dict] = None,
            on_page=None, empty_pages: Optional[list] = None) -> Iterator[tuple[Rec, dict]]:
    r = _reader(path)
    window = int(table.get("pair_window") or 0)
    start_page = (resume or {}).get("page", 0)
    rows = (resume or {}).get("rows", 0)
    for pi in range(start_page, len(r.pages)):
        lines = page_lines(r.pages[pi])
        if not any(l.strip() for l in lines) and empty_pages is not None:
            empty_pages.append(pi + 1)
        recs = []
        if window:
            ex = TextModeExtractor(window=window, table="text")
            for j, l in enumerate(lines):
                recs += list(ex.feed(f"p{pi + 1}:L{j + 1}", j + 1, None, None, l))
            recs += list(ex.finish())
        else:
            for j, l in enumerate(lines):
                if l.strip():
                    x = single_line_record(f"p{pi + 1}:L{j + 1}", j + 1, None, None, l, "text")
                    if x is not None:
                        recs.append(x)
        for k, x in enumerate(recs):
            rows += 1
            yield x, ({"page": pi + 1, "rows": rows} if k == len(recs) - 1 else None)
        if on_page:
            on_page(pi + 1, len(r.pages))
        if not recs:
            yield None, {"page": pi + 1, "rows": rows}


def read_page_lines(path, pages: set[int]) -> dict[int, list[str]]:
    r = _reader(path)
    return {p: page_lines(r.pages[p - 1]) for p in sorted(pages) if 1 <= p <= len(r.pages)}
