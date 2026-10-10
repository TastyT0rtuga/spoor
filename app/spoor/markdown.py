"""Minimal, safe Markdown -> HTML for viewing the report inside the dashboard (offline).

Supports what the report uses: headings, paragraphs, lists and checklists, pipe tables,
fenced code, blockquotes, links, images, bold/italic/strikethrough, inline code and the
<a id="..."></a> anchors. Everything else is escaped. Citation code spans get a data attribute
so the dashboard can open the cited place in the original file."""
from __future__ import annotations

import html
import re

CITE_CODE = re.compile(r"^S\d{2,}:\S+$")
ANCHOR = re.compile(r'^<a id="([A-Za-z0-9_-]+)"></a>$')


def _inline(t: str) -> str:
    out = []
    i = 0
    # split out code spans first so their content is not formatted
    parts = re.split(r"(``.+?``|`[^`]+`)", t)
    for part in parts:
        if part.startswith("``") and part.endswith("``") and len(part) > 4:
            code = part[2:-2].strip()
            out.append(_code_span(code))
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            out.append(_code_span(part[1:-1]))
        else:
            out.append(_fmt(part))
        i += 1
    return "".join(out)


def _code_span(code: str) -> str:
    code = code.replace("\\|", "|")
    e = html.escape(code)
    if CITE_CODE.match(code):
        return f'<code class="cite" data-cite="{e}" title="Open the cited place in the original file">{e}</code>'
    return f"<code>{e}</code>"


def _fmt(t: str) -> str:
    t = t.replace("\\|", "\x00PIPE\x00").replace("\\\\", "\x00BSL\x00")
    t = html.escape(t, quote=False)
    t = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", lambda m: f'<img alt="{m.group(1)}" src="{_url(m.group(2))}">', t)
    t = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", lambda m: f'<a href="{_url(m.group(2))}">{m.group(1)}</a>', t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", t)
    t = re.sub(r"~~(.+?)~~", r"<del>\1</del>", t)
    t = t.replace("&amp;lt;", "&lt;").replace("&amp;gt;", "&gt;")
    return t.replace("\x00PIPE\x00", "|").replace("\x00BSL\x00", "\\")


def _url(u: str) -> str:
    u = html.unescape(u)
    if re.match(r"(?i)^\s*(javascript|data|vbscript):", u):
        return "#"
    return html.escape(u, quote=True)


def _split_row(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    cells, cur, i = [], [], 0
    in_code = False
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            cur.append("\\|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    cells.append("".join(cur).strip())
    return cells


def _slug(t: str) -> str:
    t = re.sub(r"<[^>]+>", "", t).lower()
    return re.sub(r"[^a-z0-9]+", "-", t).strip("-")[:80]


def render(md: str) -> str:
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    para: list[str] = []

    def flush_para():
        if para:
            out.append("<p>" + _inline(" ".join(p.strip() for p in para)) + "</p>")
            para.clear()

    while i < n:
        line = lines[i]
        s = line.strip()
        if not s:
            flush_para()
            i += 1
            continue
        m = ANCHOR.match(s)
        if m:
            flush_para()
            out.append(f'<a id="{m.group(1)}"></a>')
            i += 1
            continue
        if s.startswith("```"):
            flush_para()
            lang = s[3:].strip()
            buf = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            cls = f' class="lang-{html.escape(lang)}"' if lang else ""
            out.append(f"<pre{cls}><code>" + html.escape("\n".join(buf)) + "</code></pre>")
            continue
        h = re.match(r"^(#{1,6})\s+(.*)$", s)
        if h:
            flush_para()
            lvl = len(h.group(1))
            txt = _inline(h.group(2))
            out.append(f'<h{lvl} id="{_slug(h.group(2))}">{txt}</h{lvl}>')
            i += 1
            continue
        if re.match(r"^(-{3,}|\*{3,})$", s):
            flush_para()
            out.append("<hr>")
            i += 1
            continue
        if s.startswith(">"):
            flush_para()
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + render("\n".join(buf)) + "</blockquote>")
            continue
        if s.startswith("|") and i + 1 < n and re.match(r"^\|?\s*:?-{3,}", lines[i + 1].strip()):
            flush_para()
            head = _split_row(s)
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(_split_row(lines[i]))
                i += 1
            t = ['<div class="tbl"><table><thead><tr>' + "".join(f"<th>{_inline(c)}</th>" for c in head) + "</tr></thead><tbody>"]
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            out.append("".join(t))
            continue
        if re.match(r"^([-*+]|\d+[.)])\s+", s):
            flush_para()
            ordered = bool(re.match(r"^\d+[.)]", s))
            items = []
            while i < n and re.match(r"^\s*([-*+]|\d+[.)])\s+", lines[i]):
                item = re.sub(r"^\s*([-*+]|\d+[.)])\s+", "", lines[i])
                i += 1
                while i < n and lines[i].startswith("  ") and lines[i].strip() and not re.match(r"^\s*([-*+]|\d+[.)])\s+", lines[i]):
                    item += " " + lines[i].strip()
                    i += 1
                cb = re.match(r"^\[( |x|X)\]\s+(.*)$", item)
                if cb:
                    checked = " checked" if cb.group(1).lower() == "x" else ""
                    items.append(f'<li class="task"><input type="checkbox" disabled{checked}> {_inline(cb.group(2))}</li>')
                else:
                    items.append(f"<li>{_inline(item)}</li>")
            tag = "ol" if ordered else "ul"
            out.append(f"<{tag}>" + "".join(items) + f"</{tag}>")
            continue
        para.append(line)
        i += 1
    flush_para()
    return "\n".join(out)
