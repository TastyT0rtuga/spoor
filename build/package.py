"""Build the release ZIP from this checkout (after build/fetch_deps.py):

  1. remove caches; refuse to package a tree with cases, logs or settings in it
  2. write PROGRAM.sha256 — SHA-256 of every program file (app, runtime, vendor, demo, tests,
     LICENSES and the root launchers/README); SELFTEST.bat checks the installed copy against it
  3. zip everything (plus an empty cases/ and the geoip/ and watchlists/ data) under a top-level
     Spoor/ folder into dist/Spoor-<version>.zip, and write dist/SHA256SUMS.txt

usage:  python build/package.py [--out DIR]
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROGRAM_DIRS = ["app", "runtime", "vendor", "demo", "tests", "LICENSES"]
DATA_DIRS = ["geoip", "watchlists"]
ROOT_FILES = ["Spoor.bat", "SELFTEST.bat", "spoor-cli.bat", "spoor.sh", "README.md", "LICENSE", "requirements.txt"]
EXCLUDE_NAMES = {"__pycache__", ".DS_Store", "Thumbs.db", ".gitkeep"}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    out_dir = ROOT / "dist"
    if "--out" in sys.argv:
        out_dir = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
    version = re.search(r'__version__\s*=\s*"([^"]+)"', (ROOT / "app/spoor/__init__.py").read_text("utf-8")).group(1)

    for d in list(ROOT.rglob("__pycache__")):
        shutil.rmtree(d)
    for f in list(ROOT.rglob("*.pyc")):
        f.unlink()
    for required in ("runtime/python/python.exe", "vendor/openpyxl", "vendor/maxminddb"):
        if not (ROOT / required).exists():
            sys.exit(f"missing {required}: run build/fetch_deps.py first")
    if not list((ROOT / "geoip").glob("*.mmdb")):
        print("WARNING: no .mmdb files in geoip/ — the package will have no offline ASN/country data")
    stray = [p for p in (ROOT / "cases").iterdir() if p.name != ".gitkeep"] if (ROOT / "cases").exists() else []
    for name in ("settings.json", "logs"):
        if (ROOT / name).exists():
            stray.append(ROOT / name)
    if stray:
        sys.exit("refusing to package a tree with case data in it: " + ", ".join(str(s.relative_to(ROOT)) for s in stray))

    # program manifest
    files: list[Path] = [ROOT / f for f in ROOT_FILES if (ROOT / f).exists()]
    for d in PROGRAM_DIRS:
        files += [p for p in (ROOT / d).rglob("*") if p.is_file() and not (set(p.relative_to(ROOT).parts) & EXCLUDE_NAMES)]
    files.sort(key=lambda p: p.relative_to(ROOT).as_posix())
    lines = [f"# Spoor {version} program files, SHA-256. Checked by SELFTEST.bat.",
             f"# Generated {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC. "
             "geoip/, watchlists/ and cases/ are data you may change, so they are not listed."]
    lines += [f"{sha256(p)}  {p.relative_to(ROOT).as_posix()}" for p in files]
    manifest = ROOT / "PROGRAM.sha256"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"PROGRAM.sha256: {len(files)} files")

    # zip
    out_dir.mkdir(parents=True, exist_ok=True)
    zpath = out_dir / f"Spoor-{version}.zip"
    if zpath.exists():
        zpath.unlink()
    members = files + [manifest]
    for d in DATA_DIRS:
        members += [p for p in (ROOT / d).rglob("*") if p.is_file() and not (set(p.relative_to(ROOT).parts) & EXCLUDE_NAMES)]
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in sorted(members, key=lambda p: p.relative_to(ROOT).as_posix()):
            z.write(p, "Spoor/" + p.relative_to(ROOT).as_posix())
        z.writestr(zipfile.ZipInfo("Spoor/cases/"), b"")
    digest = sha256(zpath)
    (out_dir / "SHA256SUMS.txt").write_text(f"{digest}  {zpath.name}\n", encoding="utf-8")
    print(f"{zpath} ({zpath.stat().st_size / 2**20:.1f} MB)\nSHA-256 {digest}\n{out_dir / 'SHA256SUMS.txt'}")


if __name__ == "__main__":
    main()
