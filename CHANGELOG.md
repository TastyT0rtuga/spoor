# Changelog

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
