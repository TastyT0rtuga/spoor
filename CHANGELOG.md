# Changelog

## 1.1.0 — in development

- **Reference cell-site library (bring your own lists).** Put carrier tower lists (CSV/TXT/XLSX/XLS/ZIP)
  in `cellsites/` and run `spoor cellsites index`; records the case's own lists don't place are matched
  by ECI to the list of the return's carrier (case setting `tel_carrier`, else the return's file name:
  CDR_Mediations / TWD_ / TimingAdvance = T-Mobile, ReportAU / ReportTOWER = AT&T, CellSites-CDR / VoLTE =
  Verizon, CXM_HDA = UScellular). An ECI named by several carriers at different places is left unlocated
  unless the carrier is known. Each placed record cites the list file and row (`calls.loc_cite`);
  REVIEW.md lists every list used with its SHA-256; METHODS.md describes the rules. `spoor cellsites
  status|lookup <ECI>`. No lists are shipped; `cellsites/` is git-ignored apart from its README.
- Tower-list reading: 5G NCI/NCGI values are no longer mistaken for LTE ECIs (ECI is capped at 28
  bits); Sprint's zero-padded `eNodeB-cell` form; coordinates written with Excel's leading apostrophe;
  AT&T `SECTOR_ORIENTATION` and `ANT_LAT`/`ANT_LONG`/`ANT_ORIENTATION`/`ANT_BEAMWIDTH` columns; azimuth,
  beamwidth and coordinate columns are judged on their non-NULL values.

- **Figures stage** (after Report, before Verify): deterministic SVG figures drawn from the findings,
  no language model involved; same findings in, byte-identical SVG out.
  - Figure 1, activity timeline: one lane per account, banded bars per UTC bin (minute to year,
    whichever fits), local zone as a second scale, long silences cut from the axis, numbered
    priority-1 event markers with a key.
  - Figure 2, account–IP link chart: one panel per linked-account group, shared IPs in the middle,
    lines labelled with record counts, the closest co-use in the accent colour.
  - Every mark carries its finding (visible text or numbered marker, plus tooltip); FIGURES.md has a
    sources table per figure (marker → finding → cited records → read-only SQL) and the queries that
    return exactly what is drawn. REPORT.md embeds the figures; METHODS.md describes them;
    REVIEW.md has a tick-box per figure; CITATION_CHECK.md confirms the findings shown in figures.
  - Caps (Analysis settings) are printed on the figure; labels are measured with the bundled fonts and
    shortened with an ellipsis when needed; an automatic checker enforces the grid, safety and layout.
  - Dashboard: figures inline in the report viewer; markers open the cited record, lane names the finding.
  - CLI: `spoor figures "Case"`; `spoor run --no-figures`.
- New per-account "activity over time" findings (priority 3), so every timeline lane cites a finding.
- Linked-group findings store their full account and IP lists; their reproduce-SQL applies the same
  address-class and shared-infrastructure filters as the analysis.
- Self-test: 4 new checks (figures drawn, layout and safety, reproducible, cited findings re-read).
- **Telecom returns** (call detail records and cell-site lists), any number of returns at once:
  - Column mapping learns originating/terminating number, duration, first/last cell, latitude,
    longitude, azimuth, beamwidth, site name, IMEI and IMSI (every choice editable under Sources);
    a 'Cell' column holding phone numbers is not mistaken for a cell site. Target numbers named in
    a preamble ("Target Number:", "MSISDN:") become the default account; numbers are E.164.
  - New `tel` and `cell_sites` tables and a `calls` view (also available to Ask). Each call record
    is placed at its cell site from inline coordinates or a tower list (same folder first; lists
    that disagree are not used), and cites the tower-list row it was located from. A target that no
    file names is inferred from the data and flagged as a priority-1 assumption.
  - Findings ("Calls, texts & cell sites"): per-target profile and top contacts; direct contact
    between targets; numbers in contact with 2+ targets and the target-by-target overlap table;
    IMEIs/IMSIs on 2+ targets; handset/SIM changes; co-location (cell sites within 100 m within
    15 minutes, across carriers by coordinates), stated as site co-location, not presence together.
  - `exports/telecom.kml` (cell sites, sector wedges, time-stamped records per target, co-location;
    no external references) and five telecom CSV exports.
  - Figure 3, target–contact chart; co-location occasions marked on figure 1.
  - Call records are no longer repeated as counterparty, shared-identifier or "other phones in this
    account's records" findings (numbers that also appear in non-telecom records still are).
  - Fictional telecom demo returns (`demo/telecom`, generator `tests/make_telecom_demo.py`);
    10 new self-test checks; telecom unit and resume tests. 420,000 call records ran end to end in
    about 3.5 minutes (no AI) using under 0.5 GB.
- **Carrier layouts** (checked against real-world formats; fixtures are fictional):
  - One cell identity for every carrier: decimal ECI / LTE_CI / E_CGI / CGI, hex ECGI ('311480-0c82216'),
    'MCC-MNC-eNodeB-cell', 15-digit ECGI, eNodeB + sector / cell-face columns, AT&T CellLocation
    '[ECI:eNodeB:lon:lat:az:...]'. Tower lists joined on it (same folder first); missing azimuth and
    beamwidth taken from the list.
  - Tower lists recognised even with a list-date column; report text files with several tables (voice +
    data; one tower-dump section per search) read table by table; a bare carriage return inside a quoted
    cell no longer breaks a CSV.
  - Targets from carrier file-naming conventions and preamble labels ('o Target MSISDN :', 'Voice Usage
    For:'); MTN as an account column; GMT/UTC column preferred when the carrier gives local time too; a
    midnight-only date column combined with its 'time' column; Verizon CPN / Called # as the two parties;
    MF (forwarded) legs kept but not counted; RCS chats counted with texts; IMEIs compared on 14 digits and
    spreadsheet-damaged (scientific-notation) IMEIs/IMSIs flagged.
  - **Tower dumps**: the phone on the tower is the record's subject; dumps from any number of carriers are
    grouped into scenes by time; phones and handsets at 2+ scenes and dump phones that are targets or their
    contacts are reported. Tower-dump phones are not reported as targets.
  - **Timing advance and pings**: kept as device location estimates (with the carrier's confidence), apart
    from cell sites; timing-advance reports (requested by IMSI) filed under the number whose CDR shows that
    IMSI; not counted as data usage.
  - KML: only the cell sites the records used; folders for location estimates and tower dumps.
  - Fictional carrier-layout demo returns (`demo/carrier_layouts`, generator `tests/make_carrier_layouts.py`);
    5 new self-test checks; layout, parser and isolation tests (ordinary files are never split into tables).
  - Non-telecom returns are unchanged: identical findings, report text and figure bytes to the 1.1.0
    figures build on the demo returns (compared after these changes).
- Fix: the citation check failed records whose time came from separate date and time columns.
- In telecom records, types written only as 'Text'/'SMS-MO'/'SMS-MT' are classified as communication.
- Returns that are not telecom returns are read exactly as in 1.1.0's figures build: same records, findings,
  report text and figure bytes (tested by comparing both versions on the demo returns).

## 1.0.0 — first public release

- Readers for CSV/TSV/pipe/semicolon (any encoding, incl. Windows-1251 and UTF-16), Excel
  (.xlsx/.xlsm/.xls, hidden sheets included), JSON and JSON Lines (streamed), HTML tables and
  key/value pages, PDF text per page (no OCR), plain text and logs, ZIP (members hashed and cited).
- Time-zone handling with per-file basis and priority-1 assumptions, DST ambiguity flags,
  day/month-order proof, no invented times.
- Analyses: data quality, IP addresses (with offline DB-IP ASN/country data), logins and security,
  timing, cross-source links (with Mermaid link diagrams and link-chart CSVs), identifiers with
  checksum verification (Base58Check, Bech32/Bech32m, EIP-55, Luhn), counterparties, watchlists.
- Markdown report set (REPORT, FINDINGS, EVIDENCE, SOURCES, TIMELINE, REVIEW, METHODS,
  CITATION_CHECK) with embedded SVG charts, CSV exports, and a hashed report manifest.
- Citation self-check that re-reads every cited record from the original files.
- Resumable background jobs with checkpoints (byte offset / row / page) and crash recovery.
- Optional local model (Ollama-compatible): verified summary sentences, read-only SQL "Ask".
- Local dashboard (127.0.0.1, per-launch token, Host and CSRF checks) with source-mapping editor,
  findings browser, lookup, ask and report viewer; light/dark; bundled Atkinson Hyperlegible fonts.
- Windows package with embedded Python 3.13, vendored libraries, program manifest and checksums;
  `spoor.sh` for Linux/WSL; 51-check self-test and developer test suite.
