"""Redraw the example figures in docs/ from the bundled fictional demo returns (shown in the README).

usage:  python build/make_docs_figures.py      (after build/fetch_deps.py, so the offline ASN/country data is present)

Runs the demo case in a temporary folder with the language model switched off and copies its
report/figures/*.svg into docs/. The figures are deterministic: the same code and data give the same bytes."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "app"), str(ROOT / "vendor")]


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="spoor-docs-"))
    try:
        os.environ["SPOOR_CASES"] = str(tmp / "cases")
        os.environ["SPOOR_SETTINGS"] = str(tmp / "settings.json")
        (tmp / "settings.json").write_text(json.dumps({"llm": {"enabled": False, "url": "http://127.0.0.1:9"}}), encoding="utf-8")
        from spoor.jobs import start_job
        from spoor.selftest import make_demo_case
        if not list((ROOT / "geoip").glob("*.mmdb")):
            print("note: no geoip/*.mmdb - IP boxes will show the address class instead of ASN and country")
        c = make_demo_case(run=False)
        start_job(c, c.db(), "run", {"llm": False}, wait=True)
        out = ROOT / "docs"
        out.mkdir(exist_ok=True)
        for p in sorted((c.report_dir / "figures").glob("FIG*.svg")):
            shutil.copyfile(p, out / p.name)
            print(f"docs/{p.name}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
