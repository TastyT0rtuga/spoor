"""Fetch everything the Windows package needs that is NOT kept in git, on an internet-connected
machine, into this checkout:

  runtime/python/   the Python 3.13 Windows embeddable package (SHA-256 pinned below), with the
                    ._pth file that puts app/ and vendor/ on the path and keeps `site` off
  vendor/           the pinned pure-Python libraries, unpacked from their wheels (maxminddb's
                    win_amd64 wheel: it carries a C extension plus a pure-Python fallback)
  geoip/            DB-IP "IP to ASN Lite" and "IP to Country Lite" for the newest month available
                    (CC BY 4.0; see geoip/README.txt)

usage:  python build/fetch_deps.py            (everything)
        python build/fetch_deps.py --no-geoip  (skip the 20 MB of network data)
Then:   python build/package.py                (PROGRAM.sha256 + dist/Spoor-<version>.zip)

Every download is checked: python.org by the pinned SHA-256, wheels by pip's own hash checking
(the hashes are pinned in build/requirements-vendor.txt), DB-IP by its gzip integrity and a
successful open with maxminddb.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "build" / "cache"

PY_VERSION = "3.13.16"
PY_URL = f"https://www.python.org/ftp/python/{PY_VERSION}/python-{PY_VERSION}-embed-amd64.zip"
PY_SHA256 = "97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297"
PTH = "python313.zip\n.\n..\\..\\app\n..\\..\\vendor\n\n# Spoor: app and vendored pure-Python packages are added above; site is not imported.\n#import site\n"

DBIP_FILES = ("dbip-asn-lite-{ym}.mmdb", "dbip-country-lite-{ym}.mmdb")
DBIP_URL = "https://download.db-ip.com/free/{name}.gz"


def log(msg: str) -> None:
    print(f"[fetch] {msg}", flush=True)


def download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        log(f"cached {dest.name}")
        return dest
    log(f"downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Spoor-build/1.0 (+https://github.com/TastyT0rtuga/spoor)"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    return dest


def fetch_runtime() -> None:
    target = ROOT / "runtime" / "python"
    z = download(PY_URL, CACHE / Path(PY_URL).name)
    digest = hashlib.sha256(z.read_bytes()).hexdigest()
    if digest != PY_SHA256:
        z.unlink()
        sys.exit(f"python embeddable zip hash mismatch: {digest} != {PY_SHA256} (file deleted; re-run)")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    with zipfile.ZipFile(z) as zf:
        zf.extractall(target)
    pth = next(target.glob("python*._pth"))
    pth.write_text(PTH, encoding="utf-8", newline="\r\n")
    log(f"runtime/python ready ({PY_VERSION}, {pth.name} written)")


def fetch_vendor() -> None:
    vendor = ROOT / "vendor"
    wheels = CACHE / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    req = ROOT / "build" / "requirements-vendor.txt"
    cmd = [sys.executable, "-m", "pip", "download", "--dest", str(wheels), "--no-deps", "--only-binary=:all:",
           "--platform", "win_amd64", "--python-version", "3.13", "--implementation", "cp", "--abi", "cp313",
           "--require-hashes", "-r", str(req)]
    log("pip download " + " ".join(cmd[6:]))
    subprocess.run(cmd, check=True)
    if vendor.exists():
        shutil.rmtree(vendor)
    vendor.mkdir()
    for whl in sorted(wheels.glob("*.whl")):
        with zipfile.ZipFile(whl) as zf:
            zf.extractall(vendor)
        log(f"unpacked {whl.name}")
    for data_dir in vendor.glob("*.data"):  # wheel "data" trees (console scripts); not importable, not wanted
        shutil.rmtree(data_dir)
    # license texts travel with the package (LICENSES/ is in git; refresh from the wheels' metadata if present)
    for info in vendor.glob("*.dist-info"):
        for lic in list(info.glob("LICENSE*")) + list((info / "licenses").glob("*")):
            if lic.is_file():
                name = info.name.replace(".dist-info", "") + "-LICENSE.txt"
                shutil.copyfile(lic, ROOT / "LICENSES" / name)
    log("vendor/ ready")


def fetch_geoip() -> None:
    geoip = ROOT / "geoip"
    geoip.mkdir(exist_ok=True)
    today = dt.date.today()
    months = []
    y, m = today.year, today.month
    for _ in range(3):  # this month, then the two before it (DB-IP publishes around the 1st)
        months.append(f"{y:04d}-{m:02d}")
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
    for pattern in DBIP_FILES:
        got = None
        for ym in months:
            name = pattern.format(ym=ym)
            try:
                gz = download(DBIP_URL.format(name=name), CACHE / (name + ".gz"))
            except Exception as e:  # noqa: BLE001 - try the previous month
                log(f"{name}: {e}")
                continue
            data = gzip.decompress(gz.read_bytes())
            for old in geoip.glob(pattern.format(ym="*")):
                old.unlink()
            (geoip / name).write_bytes(data)
            got = name
            break
        if not got:
            sys.exit(f"could not download {pattern} for any of {months}; see geoip/README.txt for manual steps")
        try:
            sys.path.insert(0, str(ROOT / "vendor"))
            import maxminddb  # noqa: WPS433
            with maxminddb.open_database(str(geoip / got)) as r:
                meta = r.metadata()
                log(f"{got}: {meta.database_type}, built {dt.datetime.fromtimestamp(meta.build_epoch, dt.timezone.utc):%Y-%m-%d}")
        except Exception as e:  # noqa: BLE001
            log(f"{got}: downloaded (not verified with maxminddb: {e})")


if __name__ == "__main__":
    args = set(sys.argv[1:])
    CACHE.mkdir(parents=True, exist_ok=True)
    fetch_runtime()
    fetch_vendor()
    if "--no-geoip" not in args:
        fetch_geoip()
    log("done. Next: python build/package.py")
