"""Global settings (settings.json next to the app) and per-case settings (case.json)."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

from .util import app_root

DEFAULT_PARAMS = {
    # login analysis
    "burst_failures": 5,             # failed logins ...
    "burst_window_min": 10,          # ... within this many minutes = a burst
    "burst_followup_min": 30,        # look for a successful login this long after a burst
    "change_new_ip_hours": 24,       # account change from an IP first seen for the account within N hours
    # temporal
    "concurrent_window_min": 10,     # same account, different networks within N minutes
    "gap_min_days": 7,               # report inactivity gaps at least this long ...
    "gap_factor": 10,                # ... and this many times the account's median gap
    "quiet_window_hours": 6,         # width of the quietest-window search
    # IP / links
    "shared_ip_max_accounts": 25,    # IPs used by more accounts than this are treated as shared infrastructure
    "link_include_nonpublic": False, # link accounts through private/CGNAT addresses too
    "coincidence_window_min": 60,    # two accounts on one IP within N minutes = co-use
    "subnet_min_ips": 3,             # subnets listed when they hold at least N distinct IPs
    # telecom (call detail records, cell-site lists)
    "tel_coloc_window_min": 15,      # two targets on the same / co-located cell site within N minutes
    "tel_same_site_km": 0.1,         # cell sites this close are treated as one site (co-location, tower-list agreement)
    "tel_top_contacts": 10,          # contacts listed per target
    "tel_common_min_targets": 2,     # a contact shared by at least N targets is reported
    "tel_scene_gap_hours": 3,        # tower-dump records more than N hours apart belong to different scenes
    "kml_max_points": 20000,         # call records drawn in the KML (all of them are in the CSV export)
    "kml_sector_km": 1.0,            # length of the drawn sector wedges (a drawing aid - NOT a coverage estimate)
    # output limits (the full data always goes to CSV exports)
    "max_findings_per_kind": 150,
    "evidence_samples": 12,
    "table_rows": 25,
    "timeline_md_max": 5000,
    # figures (deterministic SVG in report/figures; any cap that applies is printed on the figure)
    "figures": True,
    "figure_timeline_max_accounts": 12,  # account lanes on the activity timeline
    "figure_timeline_max_markers": 12,   # numbered priority-1 markers on the activity timeline
    "figure_links_max_clusters": 3,      # linked groups (panels) on the link chart
    "figure_links_max_accounts": 12,     # accounts per link-chart panel
    "figure_links_max_ips": 16,          # shared IPs per link-chart panel
    "figure_contacts_max_targets": 12,   # target numbers on the target-contact chart
    "figure_contacts_max_contacts": 16,  # shared contacts / direct-contact pairs on the target-contact chart
    # pipeline
    "fts": True,
    "verify_hashes_at_end": True,
    "citation_check": "all",         # all | sample | off
    "pair_window": 6,
    "store_raw_max": 4000,
    # LLM
    "llm_narrative": True,
    "llm_account_profiles": 10,      # per-account verified paragraphs for the top N accounts (0 = off)
    "llm_max_sentences": 8,
}

HOSTING_KEYWORDS = [
    "amazon", "aws", "google cloud", "microsoft azure", "azure", "digitalocean", "linode", "akamai",
    "ovh", "hetzner", "vultr", "choopa", "the constant company", "leaseweb", "m247", "datacamp", "cdn77",
    "contabo", "scaleway", "online s.a.s", "hostwinds", "ionos", "godaddy", "namecheap", "psychz",
    "quadranet", "colocrossing", "hostinger", "tencent", "alibaba", "oracle", "ibm cloud", "cloudflare",
    "fastly", "packethub", "nordvpn", "expressvpn", "surfshark", "private internet access", "mullvad",
    "proton", "windscribe", "ipvanish", "hide.me", "cyberghost", "tzulo", "frantech", "buyvm", "zenlayer",
    "g-core", "gcore", "servers.com", "worldstream", "serverius", "hivelocity", "dedipath", "sharktech",
    "terrahost", "aeza", "stark industries", "pq hosting", "flokinet", "njalla", "1337 services",
    "tor exit", "torservers",
]

DEFAULT_SETTINGS = {
    "cases_dir": "",
    "port": 8765,
    "display_tz": "America/New_York",
    "llm": {
        "enabled": True,
        "provider": "ollama",           # ollama | openai (any OpenAI-compatible local server)
        "url": "http://127.0.0.1:11434",
        "model": "auto",
        "sql_model": "",
        "num_ctx": 8192,
        "num_thread": 8,
        "temperature": 0,
        "seed": 42,
        "timeout_s": 3600,
    },
}
PREFERRED_MODELS = [
    "qwen2.5:7b-instruct-q4_K_M", "qwen2.5:7b-instruct", "qwen2.5:7b", "qwen2.5-coder:7b-instruct",
    "qwen2.5-coder:7b", "qwen3:8b", "llama3.1:8b-instruct-q4_K_M", "llama3.1:8b", "gemma3:4b",
    "qwen2.5:3b-instruct", "qwen2.5:3b", "llama3.2:3b",
]


def settings_path() -> Path:
    return Path(os.environ.get("SPOOR_SETTINGS") or (app_root() / "settings.json"))


def load_settings() -> dict:
    s = copy.deepcopy(DEFAULT_SETTINGS)
    p = settings_path()
    if p.exists():
        try:
            user = json.loads(p.read_text(encoding="utf-8"))
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(s.get(k), dict):
                    s[k].update(v)
                else:
                    s[k] = v
        except (OSError, ValueError):
            pass
    if not s.get("cases_dir"):
        s["cases_dir"] = str(Path(os.environ.get("SPOOR_CASES") or (app_root() / "cases")))
    return s


def save_settings(s: dict) -> None:
    p = settings_path()
    p.write_text(json.dumps(s, indent=2), encoding="utf-8")


def merged_params(case_params: dict | None) -> dict:
    p = copy.deepcopy(DEFAULT_PARAMS)
    for k, v in (case_params or {}).items():
        if k in p:
            p[k] = type(p[k])(v) if not isinstance(p[k], bool) else (v in (True, "true", "1", 1, "on"))
    return p
