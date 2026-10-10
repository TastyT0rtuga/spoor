"""Small shared helpers: hashing, encodings, formatting, logging, OS glue."""
from __future__ import annotations

import ctypes
import datetime as _dt
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

UTC = _dt.timezone.utc
IS_WINDOWS = os.name == "nt"


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(UTC)


def utc_now_str() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")


def local_now_str() -> str:
    return _dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z (UTC%z)")


def app_root() -> Path:
    """Folder that holds app/, vendor/, runtime/, geoip/, watchlists/."""
    return Path(__file__).resolve().parent.parent.parent


def sha256_file(path, progress=None, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            if progress:
                progress(len(b))
    return h.hexdigest()


def jdump(obj, indent=None) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str, indent=indent, sort_keys=False)


def jload(s, default=None):
    if s is None or s == "":
        return default
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return default


def fmt_int(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def fmt_num(x) -> str:
    if x is None:
        return ""
    if isinstance(x, float):
        if x.is_integer():
            return f"{int(x):,}"
        return f"{x:,.2f}"
    if isinstance(x, int):
        return f"{x:,}"
    return str(x)


def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "unknown"
    s = int(max(0, seconds))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def slug(s: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s.strip()).strip("-._")
    return (s or "case")[:maxlen]


def md_escape(s) -> str:
    """Escape text for a Markdown table cell (keeps content verbatim when rendered)."""
    if s is None:
        return ""
    s = str(s).replace("\r", " ").replace("\n", " ⏎ ")
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return s


def md_code(s, maxlen: int = 400) -> str:
    """Render text as inline code safely (verbatim content, pipes escaped for tables)."""
    if s is None:
        return ""
    s = str(s).replace("\r", " ").replace("\n", " ⏎ ")
    if len(s) > maxlen:
        s = s[:maxlen] + " …[truncated]"
    ticks = "``" if "`" in s else "`"
    s = s.replace("|", "\\|")
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{ticks}{pad}{s}{pad}{ticks}"


# ---------------------------------------------------------------- encodings

_CYR = re.compile(r"[Ѐ-ӿ]")
_LAT_EXT = re.compile(r"[À-ÿ]")


def detect_encoding(sample: bytes) -> str:
    """Pick an encoding for text data. Deterministic, conservative."""
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return "utf-16"
    # UTF-16 without BOM: many NULs at odd/even positions
    if len(sample) > 64:
        nul_odd = sample[1::2].count(0)
        nul_even = sample[0::2].count(0)
        half = len(sample) // 2
        if nul_odd > half * 0.4 and nul_even < half * 0.05:
            return "utf-16-le"
        if nul_even > half * 0.4 and nul_odd < half * 0.05:
            return "utf-16-be"
    try:
        sample.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as e:
        # a multi-byte char cut at the end of the sample is still UTF-8
        if e.start >= len(sample) - 4:
            try:
                sample[: e.start].decode("utf-8")
                return "utf-8"
            except UnicodeDecodeError:
                pass
    hi = sum(1 for b in sample if b >= 0xC0)
    if hi:
        cyr = len(_CYR.findall(sample.decode("cp1251", "replace")))
        lat = len(_LAT_EXT.findall(sample.decode("cp1252", "replace")))
        # Cyrillic text in cp1251 produces long runs of 0xC0-0xFF bytes
        runs = len(re.findall(rb"[\xc0-\xff]{3,}", sample))
        if cyr and runs >= max(2, hi // 20):
            return "cp1251"
        if lat:
            return "cp1252"
    return "cp1252"


# ---------------------------------------------------------------- logging

def get_logger(case_dir: Path | None = None, name: str = "spoor") -> logging.Logger:
    log = logging.getLogger(name)
    if getattr(log, "_spoor_ready", False):
        return log
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    if case_dir is not None:
        (Path(case_dir) / "logs").mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(Path(case_dir) / "logs" / "run.log", encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    log._spoor_ready = True  # type: ignore[attr-defined]
    return log


# ---------------------------------------------------------------- OS glue

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


def keep_awake(on: bool) -> bool:
    """Ask Windows not to idle-sleep while a long job runs. No-op elsewhere."""
    if not IS_WINDOWS:
        return False
    try:
        flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0)
        return bool(ctypes.windll.kernel32.SetThreadExecutionState(flags))  # type: ignore[attr-defined]
    except Exception:
        return False


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    if IS_WINDOWS:
        try:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            k = ctypes.windll.kernel32  # type: ignore[attr-defined]
            k.OpenProcess.restype = ctypes.c_void_p
            k.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            k.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            k.CloseHandle.argtypes = [ctypes.c_void_p]
            h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not h:
                return False
            code = ctypes.c_ulong()
            ok = k.GetExitCodeProcess(h, ctypes.byref(code))
            k.CloseHandle(h)
            return bool(ok) and code.value == 259  # STILL_ACTIVE
        except Exception:
            return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    # zombie check on Linux
    try:
        with open(f"/proc/{int(pid)}/stat", "r") as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return True


def open_in_file_manager(path: Path) -> None:
    path = Path(path)
    if IS_WINDOWS:
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def spawn_detached(args: list[str], log_path: Path, low_priority: bool = True) -> int:
    """Start a worker process that survives the UI/console closing."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    out = open(log_path, "ab")
    kw: dict = dict(stdin=subprocess.DEVNULL, stdout=out, stderr=out, close_fds=True)
    if IS_WINDOWS:
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NO_WINDOW = 0x08000000
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
        flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
        if low_priority:
            flags |= BELOW_NORMAL_PRIORITY_CLASS
        kw["creationflags"] = flags | 0x01000000  # CREATE_BREAKAWAY_FROM_JOB: survive the console closing
        try:
            p = subprocess.Popen(args, **kw)
        except OSError:
            kw["creationflags"] = flags           # the job does not allow breakaway
            p = subprocess.Popen(args, **kw)
        out.close()
        return p.pid
    kw["start_new_session"] = True
    p = subprocess.Popen(args, **kw)
    out.close()
    return p.pid
