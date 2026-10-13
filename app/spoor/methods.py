"""METHODS.md: what the tool did, with which parameters and data, and its limits."""
from __future__ import annotations

import platform
import sqlite3
import sys

from . import __version__
from . import db as dbm
from .config import HOSTING_KEYWORDS
from .ipaddr import CLASS_NOTES, V4_NETS, V6_NETS
from .timeparse import ABBR
from .util import md_escape, utc_now_str


def _t(columns, rows) -> str:
    out = ["| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for r in rows:
        out.append("| " + " | ".join(md_escape(x) for x in r) + " |")
    return "\n".join(out)


def methods_text(case, con) -> str:
    p = case.params
    geo = dbm.get_meta(con, "geoip") or {}
    nar = dbm.get_meta(con, "narrative") or {}
    llm_used = dbm.rows(con, "SELECT purpose, model, model_digest, options, COUNT(*) AS n FROM llm_calls GROUP BY purpose, model, model_digest")
    from .analyses.watchlist import load_watchlists
    wl = {}
    for w in load_watchlists(case):
        wl.setdefault(w["file"], (w["sha256"], 0))
        wl[w["file"]] = (w["sha256"], wl[w["file"]][1] + 1)
    L = [f"# Methods — {case.name}", "", f"Generated {utc_now_str()} by Spoor {__version__}.", ""]
    L += ["## Environment", "", _t(["Item", "Value"], [
        ["Spoor", __version__], ["Python", sys.version.split()[0]], ["SQLite", sqlite3.sqlite_version],
        ["Operating system", platform.platform()], ["Network access", "none required; the tool makes no outbound connections "
                                                     "(the only network call is to the local model server, if configured, on this machine)"],
        ["Case database", "case.db (SQLite). Findings quote read-only SQL that reproduces them."]]), ""]
    L += ["## Processing steps", "",
          "1. **Register and hash.** Each file is hashed (SHA-256) before it is read. ZIP archives are extracted into the case "
          "folder and each member is hashed and given its own label. Byte-identical duplicates are recorded and read once.",
          "2. **Scan and map.** The format, encoding, header row, delimiter and column meanings are detected and recorded per "
          "file, with the reason for each choice (SOURCES.md). The analyst can change any mapping, timezone, date order, default "
          "account or default event type before the analysis; the change is logged and the file is re-read.",
          "3. **Ingest.** Every record is stored with its exact location in the original file (line and byte offset, worksheet row, "
          "PDF page and line, HTML line and column, or JSON path) and its verbatim text. Timestamps are converted to UTC with the "
          "basis of the conversion recorded per record. IP addresses are normalised and classified. Identifiers are extracted and validated.",
          "4. **Analyse.** Deterministic SQL and Python analyses produce findings. Each finding stores the values it states, the "
          "records it rests on, and a reproducing query. Finding numbers are assigned in a fixed order.",
          "5. **Report.** Markdown files and CSV exports are written; a SHA-256 manifest covers the report folder.",
          "6. **Figures.** Deterministic SVG figures are drawn from the findings (see Figures below); a figure that fails is "
          "listed in REVIEW.md and does not stop the run.",
          "7. **Citation check.** Cited records are located again in the original files and compared with the stored text; "
          "source hashes are recomputed.",
          "8. **Optional AI draft.** A local language model may draft summary sentences from the findings. Every sentence is "
          "verified mechanically (below); failures are removed and listed in REVIEW.md.", ""]
    L += ["## Reading files", "", _t(["Format", "How it is read", "Citation form"], [
        ["CSV / TSV / pipe / semicolon", "delimiter and header detected from the first 400 lines; preamble lines kept for context; lines "
         "that do not fit the table are read as free text and counted", "S01:L120 (physical line; multi-line records L120-122)"],
        ["Plain text, logs, mbox", "each line with a timestamp, IP or identifier becomes a record", "S01:L120"],
        ["XLSX / XLSM / XLS", "every sheet, including hidden ones; header row detected per sheet; Excel dates read as wall-clock "
         "times in the source timezone", "S01:Sheet!R220"],
        ["JSON / JSON Lines", "arrays of objects become tables (nested keys flattened); other values read as text; files over 512 MB "
         "streamed when they are a top-level array", "S01:$.path[17] or S01:L17"],
        ["HTML", "data tables become rows; other text becomes lines; an IP line without a timestamp is paired with the nearest "
         "timestamp line (see below)", "S01:L120 or S01:L120:C17"],
        ["PDF", "text extracted page by page (layout mode); pages without extractable text are listed as not analysed - no OCR is performed",
         "S01:p3:L14"],
        ["ZIP", "extracted (ZipCrypto passwords supported; AES-encrypted archives must be extracted with 7-Zip first)", "member files get their own labels"],
    ]), "",
          f"**Proximity pairing.** In free text, a line holding an IP but no timestamp is paired with the nearest line holding a timestamp "
          f"(and no IP) within {p.get('pair_window', 6)} lines, never across another IP line; ties go to the side most pairs used. Paired "
          "records cite every line used (L120+L122) and are flagged `paired_by_proximity`. Pairing is on by default for HTML and "
          "suggested for text/PDF only when the layout shows IPs and times on separate lines.", ""]
    L += ["## Timestamps", "",
          "- Formats: ISO 8601, US and day-first numeric dates, month names (English and Russian), RFC 2822 (e-mail), Apache/Nginx "
          "access-log, Unix `date`, compact `YYYYMMDDhhmmss`, and epoch seconds/milliseconds/microseconds/nanoseconds in timestamp columns.",
          "- A timestamp that carries its own offset (`Z`, `+02:00`, `UTC`, an abbreviation or an IANA zone name) is converted with it.",
          "- Otherwise the source's timezone is applied. It is taken from a header (e.g. `Time (UTC)`), the file's preamble or its name; "
          "if nothing indicates a zone, UTC is used and the assumption is flagged as priority 1 for review.",
          "- Daylight saving: a wall-clock time in the repeated hour is converted with the first occurrence and flagged "
          "`ambiguous_dst`; a time in the skipped hour is flagged `nonexistent_local_time`. A standard-time abbreviation used on a "
          "daylight-time date (or the reverse) is flagged `abbr_dst_mismatch` and converted as written.",
          "- Numeric dates: the day/month order is proven from the data (a value above 12) where possible; if every value is "
          "ambiguous, MM/DD is assumed and flagged.",
          "- Date-only values keep their calendar date (no time is invented) and are excluded from hour-of-day analysis.",
          "- Years before 1995 or after next year are flagged `implausible_year` and excluded from timing analysis.", "",
          "Abbreviations recognised (fixed offsets):", "",
          _t(["Abbreviation", "UTC offset (minutes)"], [[k, str(v[0])] for k, v in sorted(ABBR.items())]), ""]
    rng = [[c, ", ".join(str(n) for cc, n in V4_NETS + V6_NETS if cc == c), CLASS_NOTES.get(c, "")]
           for c in ["private", "cgnat", "loopback", "link-local", "multicast", "documentation", "reserved", "nat64"]]
    L += ["## IP addresses", "",
          "IPv4 addresses are normalised (leading zeros removed); IPv6 addresses are compressed; IPv4-mapped IPv6 addresses are "
          "treated as IPv4. Ports are kept when the data provides them. Subnets: /24 for IPv4, /64 for IPv6.", "",
          _t(["Class", "Ranges", "Meaning"], rng + [["public", "everything else", CLASS_NOTES["public"]]]), ""]
    if geo.get("asn") or geo.get("geo"):
        rows = []
        for k in ("asn", "geo"):
            g = geo.get(k)
            if g:
                rows.append([g["file"], g["type"], g["built"], g["sha256"]])
        L += ["**Offline network data.** Public IPs were looked up in these local databases (no network access):", "",
              _t(["File", "Type", "Built", "SHA-256"], rows), "",
              "IP to ASN Lite and IP to Country Lite data by [DB-IP](https://db-ip.com), licensed under "
              "[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Registrations and locations reflect the database build date, "
              "not necessarily the date of each event, and country-level geolocation is approximate.", "",
              "Hosting/VPN keyword list (matched against the registered network name; a match is a lead only): "
              + ", ".join(HOSTING_KEYWORDS) + ".", ""]
    else:
        L += ["No offline ASN/country database was present in `geoip/`, so no network or country lookups were made.", ""]
    L += ["## Identifiers", "", _t(["Kind", "Accepted when"], [
        ["Email address", "standard address syntax; compared in lower case"],
        ["Phone number", "formatted North American numbers (with separators or +1) validated against NANP rules; international numbers written with + and 8-15 digits; bare digit strings only in account/counterparty columns"],
        ["Bitcoin, Litecoin, Dogecoin", "Base58Check checksum and version byte verified, or Bech32/Bech32m checksum and witness program verified"],
        ["TRON", "Base58Check checksum with version 0x41 verified"],
        ["Ethereum/EVM", "0x + 40 hex digits; mixed-case addresses verified against the EIP-55 checksum (failures reported separately)"],
        ["Monero", "format and Base58 alphabet only (no checksum verification)"],
        ["MAC address", "six hex octets (colon, dash or Cisco dotted form); all-zero and broadcast excluded"],
        ["IMEI", "15 digits passing the Luhn check, only on lines or columns that mention IMEI"],
        ["URL", "http(s) URLs"]]), ""]
    L += ["## Event types", "",
          "Each record's event type is read from the mapped event/activity and status columns using keyword rules (English and "
          "Russian): logout, login (failed when the status or text indicates failure), registration, account change (password, "
          "2FA/MFA, recovery, e-mail/phone changes, API keys, withdrawal addresses), communication, transaction, other. When a "
          "table has no event column, the table's default type applies (suggested from the file or sheet name, shown in "
          "SOURCES.md and REVIEW.md). Free-text lines without a timestamp are attributes, not events. The original event text "
          "is always kept and shown next to the derived type.", ""]
    L += ["## Analyses and parameters", "", _t(["Analysis", "What it reports", "Parameters"], [
        ["Sources & data quality", "per-file counts, time range, timezone basis; assumptions; unparsed values; pages without text; duplicates", "-"],
        ["IP inventory and notable IPs", "IPs in 2+ sources or used by 2+ accounts, with the closest records of two accounts on the same IP",
         f"IPs used by more than {p['shared_ip_max_accounts']} accounts are treated as shared infrastructure"],
        ["Address types and ports", "private/CGNAT/other non-public addresses; how many public IPv4 events carry a source port", "-"],
        ["Networks", "ASN and country distribution; networks whose names match the hosting/VPN keyword list", "offline DB-IP data"],
        ["Legal-process list", "every public IP with each UTC timestamp (and port) for follow-on requests", "exports/ip_legal_process.csv"],
        ["Logins", "per-account totals; failed-login bursts and any successful login after them; IPs failing on 3+ accounts; "
         "account changes made from an IP first seen for that account shortly before",
         f"burst = {p['burst_failures']}+ failures within {p['burst_window_min']} min; follow-up {p['burst_followup_min']} min; "
         f"new IP = first seen within {p['change_new_ip_hours']} h"],
        ["Timing", "hour-of-day and weekday profiles (UTC and the case zone), quietest window, daily spikes, inactivity gaps, rapid network switches",
         f"quiet window {p['quiet_window_hours']} h; spike = 5x median day (min 10); gap >= {p['gap_min_days']} days and >= "
         f"{p['gap_factor']}x the median interval; switch window {p['concurrent_window_min']} min"],
        ["Links", "accounts connected through shared IPs; identifiers shared across accounts or sources; link-chart CSVs",
         f"co-use window {p['coincidence_window_min']} min (priority); non-public addresses {'included' if p['link_include_nonpublic'] else 'excluded'}"],
        ["Identifiers", "inventory with validation; other e-mails and phones in each account's records", "-"],
        ["Counterparties", "most frequent counterparties per account; largest amounts (totals only within one currency)", "-"],
        ["Watchlists", "matches against analyst-supplied lists of IPs, ranges and identifiers", ", ".join(wl) or "none supplied"]]
        + ([["Calls, texts & cell sites", "telecom returns (call detail records and cell-site lists), any number at once: per-target "
         "profile and top contacts; direct contact between targets; numbers in contact with 2+ targets and the target-by-target "
         "overlap table; IMEIs/IMSIs on 2+ targets and handset/SIM changes; co-location; KML (exports/telecom.kml)",
         f"co-location = two targets on cell sites within {int(float(p.get('tel_same_site_km', 0.1)) * 1000)} m (or the same cell ID "
         f"in the same carrier's folder when there are no coordinates) within {p.get('tel_coloc_window_min', 15)} min; common "
         f"contact = {p.get('tel_common_min_targets', 2)}+ targets; KML draws up to {p.get('kml_max_points', 20000)} records, "
         f"sector wedges {p.get('kml_sector_km', 1.0)} km long"]] if dbm.get_meta(con, "telecom") else [])), ""]
    if dbm.get_meta(con, "telecom"):
        L += ["### Telecom returns", "",
              "- **Reading.** A table is read as telecom records when it has originating and terminating numbers, a cell / eNodeB / "
              "ECI column, an IMSI, an other party with a duration, or a phone with a location estimate (Sources -> the file -> "
              "'Read as' shows and changes every choice). A table of cell identities with coordinates and nothing about calls is a "
              "cell-site (tower) list; its dates (e.g. ListDate) describe the list and are not events. Report text files holding "
              "several tables (a voice and a data table; one section per tower-dump search) are read table by table, each named by "
              "the label above it. When a carrier gives a local time and a GMT/UTC time, the GMT/UTC column is used; a date column "
              "that is midnight on every row next to a 'time' column is combined with it.",
              "- **Target.** The row's account (MSISDN / MTN column), else the number the return names in its preamble ('Target "
              "Number:', 'o Target MSISDN :', 'Voice Usage For:'), else the number in the file name - carriers name call-record files "
              "after the target ('CDR_Mediations_<number>_...', 'CellSites-CDR_..._<number>', '..._CXM_HDA_volte_<number>_...') - "
              "else the number on one end of at least 80% of the rows. File-name and inferred targets are priority-1 assumptions in "
              "REVIEW.md. Timing-advance reports are named after the IMSI; when a call-record return shows which number used that "
              "IMSI, the records are filed under that number (cited). North American numbers are written in E.164 (+1...). "
              "Direction is from the target's side; forwarded legs (Verizon 'MF') are kept but not counted as contacts.",
              "- **Cell identity.** Every LTE cell is reduced to its ECI (eNodeB x 256 + cell), however the carrier writes it: a "
              "decimal ECI / LTE_CI / E_CGI / CGI; an ECGI 'MCC-MNC + hex ECI' (e.g. 311480-0c82216); 'MCC-MNC-eNodeB-cell' "
              "(e.g. 311580-123456-1); a 15-digit ECGI (MCC, MNC, 9-digit ECI); an eNodeB column plus the record's sector / cell-face "
              "column (e.g. 1st LTE Site ID 48221 + 1st LTE Sector ID 2; eNB ID 51234 + Cell Face 22); or AT&T's CellLocation "
              "'[ECI:eNodeB:longitude:latitude:azimuth:...]' (longitude first; 0,0 or azimuth -1 mean unknown; when several cells are "
              "listed the first is used). A tower list's 'Sector' (1/2/3) is not a cell ID and is not combined with the eNodeB.",
              "- **Cell-site locations.** A record takes coordinates written on the record itself, else those of its cell from a tower "
              "list - by ECI, or by the cell label as written when there is no ECI - preferring a list in the same folder (the same "
              "carrier); a list elsewhere is used only if every list naming that cell agrees within "
              f"{int(float(p.get('tel_same_site_km', 0.1)) * 1000)} m. Azimuth and beamwidth missing from the record are taken from "
              "the tower list entry for the same ECI. Each located record cites the tower-list row its coordinates came from.",
              "- **Handsets.** IMEIs are compared on their first 14 digits (type allocation code + serial): carriers append a Luhn "
              "check digit, a 0 or a two-digit software version. A value shown in scientific notation (e.g. 3.5E+14) was "
              "damaged by a spreadsheet before it reached Spoor and is not used (counted in the data-quality finding).",
              "- **Tower dumps.** A source is a tower dump when its file name says so (TWD_, ReportTOWER, TowerData, ...) or when it "
              "covers many phones with none on half its records. Its records are about the phone on the tower: the 'Number "
              "Associated w/Tower' / MSISDN column, else the calling number of an outgoing record and the called number of an "
              "incoming one. Dump records from any number of carriers are grouped into scenes by time (a gap of more than "
              f"{p.get('tel_scene_gap_hours', 3)} hours starts a new scene); phones and handsets seen at two or more scenes, and dump "
              "phones that are targets or contacts of targets, are reported. A dump record shows that the phone used a dumped cell "
              "in that window, not that it was at a particular address.",
              "- **Location estimates.** Timing-advance (end latitude/longitude, confidence) and ping positions are the carrier's "
              "estimate of where the DEVICE was. They are stored and drawn apart from cell sites, with the confidence as the carrier "
              "states it, and are not counted as calls or data use.",
              "- **What a location means.** A record's coordinates are those of the cell site that served it, not of the phone. "
              "Sector direction is shown but coverage area and range are not modelled; KML wedges are a fixed-length drawing aid. "
              "Co-location therefore means both phones were served by co-located sites close in time - not that the users were "
              "together. Carriers differ in whether the first/last cell and the time of seizure or of answer is recorded.",
              "- **Not analysed in this version.** 3G (LAC + cell ID, Lucent sector offsets) tower joins, per-call RTT distance "
              "reports, and the IP addresses of data sessions (unless mapped as an IP column).", ""]
    if wl:
        L += ["Watchlists used:", "", _t(["File", "Entries", "SHA-256"], [[k, str(v[1]), v[0]] for k, v in wl.items()]), ""]
    L += figures_section(con, p)
    L += ["## Language model (optional)", ""]
    if llm_used:
        L += ["Calls made in this case:", "",
              _t(["Purpose", "Model", "Model digest", "Options", "Calls"],
                 [[r["purpose"], r["model"], r["model_digest"] or "", r["options"] or "", str(r["n"])] for r in llm_used]), ""]
    L += ["The model runs locally and only sees findings (or query results), never the raw returns. It never adds facts to the "
          "report by itself. Its output is used in two ways:", "",
          "- **Summary sentences.** The model must cite finding numbers. A sentence is kept only if: it cites at least one existing "
          "finding; every IP address, e-mail, phone number, cryptocurrency address, MAC, URL, timestamp, date, number, "
          "percentage and source label in it appears in the cited findings (rounded numbers only with words like 'about'); every "
          "account name and capitalised proper name in it appears in the cited findings; and no account, IP or identifier from "
          "elsewhere in the case appears without being in the cited findings. Sentences using inference words ('likely', "
          "'suggests', 'appears', ...) or characterisations ('attacker', 'compromised', 'fraud', ...) are kept but marked ⚑. "
          "Removed sentences are listed with the reason in REVIEW.md.",
          "- **Questions (Ask).** The model writes one read-only SQL query. The query runs on a read-only connection with an "
          "authoriser that permits only reading; the answer shown is the query's own result rows (with citations). Any one-line "
          "summary the model writes about those rows is verified against them in the same way.", ""]
    if nar:
        L += [f"Summary drafted with `{nar.get('model')}`: {nar.get('accepted', 0)} sentences kept, {nar.get('flagged', 0)} of them flagged, "
              f"{nar.get('rejected', 0)} removed.", ""]
    L += ["## Limitations", "",
          "- The tool reports what the records say. It does not establish who used an account, IP or device.",
          "- Event types come from keyword rules; unusual provider wording may be typed 'other'. The original text is always shown.",
          "- Timezone, day/month order, default accounts and default event types may rest on stated assumptions; each is listed in REVIEW.md.",
          "- Text extracted from PDFs can merge or split columns; check PDF citations against the page. Scanned pages are not read (no OCR).",
          "- Offline ASN/country data reflects its build date; geolocation is approximate.",
          "- Records repeated across overlapping returns are counted once per source (see the duplicate-events finding).",
          "- Very long records are truncated in the report (full text remains in the source file at the cited location).", ""]
    return "\n".join(L) + "\n"


def figures_section(con, p: dict) -> list[str]:
    from .figures import figure_rows
    figs = figure_rows(con)
    tel_row = [["3. Target-contact chart", "Telecom target numbers either side; in the middle, one node per pair of targets in direct "
              "contact (dashed outline) and one per number in contact with two or more targets (a common-contact finding). Each line is "
              "labelled with that target's records with that number; a dashed line labelled 0 means the contact is only in the other "
              "target's records. Sides are chosen as for figure 2. The contact shared by the most targets (3 or more) is the only accent.",
              f"targets {p.get('figure_contacts_max_targets', 12)}, middle nodes {p.get('figure_contacts_max_contacts', 16)}"]] if dbm.get_meta(con, "telecom") else []
    L = ["## Figures", "",
         "Figures are drawn by Spoor itself from the findings and the case database - no language model is involved, and the same "
         "findings always give byte-identical SVG files. Each file embeds the fonts it uses (Atkinson Hyperlegible Next and Mono, "
         "SIL Open Font License) and contains no scripts and no external references. Every mark carries the finding it comes from, "
         "as visible text or a numbered marker and as an SVG tooltip; FIGURES.md lists each figure's sources, the records they cite "
         "and the queries that reproduce what is drawn. Labels too long for their box are shortened with an ellipsis on the figure "
         "and given in full in the tooltip and the sources table. Any limit that applies is printed on the figure. Layout rules: a 4 px "
         "grid, 1 px lines, one accent colour (priority 1 only), meaning never carried by colour alone; they are checked automatically "
         "every time a figure is drawn. The conventions are adapted from diagram-design by Cathryn Lavery (MIT licence).", "",
         _t(["Figure", "How it is drawn", "Limits (Analysis settings)"], [
             ["1. Activity timeline", "One lane per account (accounts named in priority-1 findings first, then the busiest; drawn in order of "
              "first activity). Bars count activity records - the TIMELINE data - per UTC bin, using the finest of minute, 5 or 15 minutes, "
              "hour, 3 or 6 hours, day, week (Monday start), month, quarter or year that fits the width; date-only records sit on their "
              "calendar date and are left out at finer than daily bins. Bar height is banded on a logarithmic scale; the bands are printed "
              "on the figure. UTC is on top and the case's local zone underneath. A silence longer than a quarter of the drawn time (and at "
              "least a week) is cut from the axis and labelled with its length in days (at most four axis pieces). Priority-1 findings "
              "whose cited records fall within 24 hours are marked at their earliest cited record and numbered in time order; for a "
              "linked-account group the closest co-use" + (", and for a telecom co-location finding the closest pair of records," if dbm.get_meta(con, "telecom") else "") + " is marked. Other priority-1 findings are listed on the figure as not tied to one moment.",
              f"lanes {p.get('figure_timeline_max_accounts', 12)}, markers {p.get('figure_timeline_max_markers', 12)}"],
             ["2. Account-IP link chart", "One panel per linked-group finding (largest first). Shared IPs in the middle, accounts either "
              "side - for up to 10 accounts every split between the sides is tried and the one with the fewest crossing lines kept. Each "
              "line joins an account to an IP it used and is labelled with that account's number of records on that IP. The closest co-use "
              "the finding reports is the only element in the accent colour.",
              f"panels {p.get('figure_links_max_clusters', 3)}, accounts per panel {p.get('figure_links_max_accounts', 12)}, "
              f"IPs per panel {p.get('figure_links_max_ips', 16)}"]] + tel_row), ""]
    if figs:
        rows = []
        for f in figs:
            state = {"ok": "drawn", "skipped": "not drawn"}.get(f["status"], "FAILED")
            extra = "; ".join(n for n in f["notes"] if not n.startswith(("Bars count", "Each line joins"))) or "-"
            rows.append([f"{f['no']}. {f['title']}", state + (f" ({f['reason']})" if f.get("reason") else ""), extra])
        L += ["In this report:", "", _t(["Figure", "Status", "Not shown / limits applied"], rows), ""]
    elif not p.get("figures", True) or (dbm.get_meta(con, "figures") or {}).get("off"):
        L += ["Figures were switched off for this run.", ""]
    return L
