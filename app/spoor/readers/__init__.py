"""Format detection and dispatch to the individual readers."""
from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Iterator, Optional

from .textmode import Rec  # noqa: F401  (re-export)

TEXT_EXT = {".csv", ".tsv", ".txt", ".log", ".dat", ".psv", ".tab", ".mbox", ".eml", ".xml", ".text", ".out", ".md"}
SKIP_EXT = {".exe", ".dll", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".mp4", ".mov", ".avi",
            ".mp3", ".wav", ".m4a", ".heic", ".webp", ".7z", ".rar", ".gz", ".tar", ".iso", ".msg", ".pst", ".ost",
            ".sqlite", ".db", ".mmdb", ".docx", ".doc", ".pptx", ".ppt", ".odt", ".ods"}


def detect_kind(path: Path) -> str:
    p = Path(path)
    ext = p.suffix.lower()
    try:
        with open(p, "rb") as f:
            head = f.read(8)
    except OSError:
        return "unreadable"
    if ext in (".xlsx", ".xlsm") and head.startswith(b"PK"):
        return "xlsx"
    if ext == ".xls" and head.startswith(b"\xd0\xcf\x11\xe0"):
        return "xls"
    if head.startswith(b"%PDF"):
        return "pdf"
    if ext == ".zip" or (head.startswith(b"PK\x03\x04") and ext not in (".xlsx", ".xlsm", ".docx", ".pptx")):
        return "zip"
    if ext in (".json", ".jsonl", ".ndjson", ".geojson"):
        return "json"
    if ext in (".html", ".htm", ".xhtml"):
        return "html"
    if ext in TEXT_EXT:
        return "text"
    if ext in SKIP_EXT:
        return "unsupported"
    # sniff: mostly printable -> text
    try:
        with open(p, "rb") as f:
            blk = f.read(65536)
    except OSError:
        return "unreadable"
    if not blk:
        return "empty"
    stripped = blk.lstrip(b"\xef\xbb\xbf \r\n\t").lower()
    if stripped.startswith((b"<!doctype html", b"<html")):
        return "html"
    if stripped.startswith((b"{", b"[")):
        return "json"
    printable = sum(1 for b in blk if 32 <= b < 127 or b in (9, 10, 13) or b >= 0x80)
    if blk.count(0) > len(blk) * 0.3 and (blk[1::2].count(0) > len(blk) * 0.4 or blk[0::2].count(0) > len(blk) * 0.4):
        return "text"  # UTF-16 text
    return "text" if printable / len(blk) > 0.95 else "unsupported"


def scan(path: Path, kind: str) -> dict:
    name = Path(path).name
    if kind == "text":
        from .delimited import scan as s
        return s(path, name)
    if kind == "xlsx":
        from .excel import scan_xlsx
        return scan_xlsx(path, name)
    if kind == "xls":
        from .excel import scan_xls
        return scan_xls(path, name)
    if kind == "json":
        from .jsonr import scan as s
        return s(path, name)
    if kind == "html":
        from .htmlr import scan as s
        return s(path, name)
    if kind == "pdf":
        from .pdfr import scan as s
        return s(path, name)
    raise ValueError(f"cannot scan kind {kind}")


def iterate(path: Path, cfg: dict, table: dict, resume: Optional[dict] = None, **kw) -> Iterator[tuple]:
    kind = cfg.get("kind")
    if kind in ("delimited", "text"):
        from .delimited import iterate as it
        return it(path, cfg, table, resume)
    if kind == "xlsx":
        from .excel import iterate_xlsx
        return iterate_xlsx(path, cfg, table, resume)
    if kind == "xls":
        from .excel import iterate_xls
        return iterate_xls(path, cfg, table, resume)
    if kind in ("json", "jsonl"):
        from .jsonr import iterate as it
        return it(path, cfg, table, resume)
    if kind == "html":
        from .htmlr import iterate as it
        return it(path, cfg, table, resume)
    if kind == "pdf":
        from .pdfr import iterate as it
        return it(path, cfg, table, resume, **kw)
    raise ValueError(f"cannot read kind {kind}")


def safe_extract_zip(zpath: Path, dest: Path, password: Optional[str] = None, max_total: int = 200 * 1024**3) -> list[tuple[str, Path]]:
    """Extract every member (zip-slip safe). Returns [(member_name, extracted_path)]."""
    out = []
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(zpath) as z:
        pwd = password.encode("utf-8") if password else None
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            parts = [p for p in name.split("/") if p not in ("", ".", "..")]
            if not parts:
                continue
            target = dest.joinpath(*parts)
            if not str(target.resolve()).startswith(str(dest.resolve())):
                continue
            total += info.file_size
            if total > max_total:
                raise ValueError("zip expands beyond the size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with z.open(info, pwd=pwd) as src, open(target, "wb") as dst:
                    while True:
                        b = src.read(1 << 20)
                        if not b:
                            break
                        dst.write(b)
            except RuntimeError as e:
                msg = str(e)
                if "password" in msg.lower() or "encrypted" in msg.lower():
                    raise ValueError(f"'{name}' is encrypted - enter the ZIP password") from e
                raise
            except NotImplementedError as e:
                raise ValueError(f"'{name}' uses unsupported compression or AES encryption - extract it with 7-Zip and add the folder") from e
            out.append((name, target))
    return out


def walk_files(root: Path, recursive: bool = True) -> list[Path]:
    root = Path(root)
    if root.is_file():
        return [root]
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.startswith("~$") or fn in ("Thumbs.db", ".DS_Store", "desktop.ini"):
                continue
            files.append(Path(dirpath) / fn)
        if not recursive:
            break
    return files
