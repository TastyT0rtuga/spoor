# Spoor — offline subpoena-return analysis

Spoor reads large legal-process returns (provider login logs, IP logs, subscriber records, exchange
and bank records, CDR-style logs), analyses them for **IP addresses, timing, logins, links between
accounts and identifiers**, and writes a **Markdown report in which every statement cites the exact
line, row, page or JSON path of the original file it comes from**. It runs entirely on this computer:
no installation, no internet, no outbound connections.

A local language model (optional) can draft a plain-English summary. It never adds facts on its own:
every sentence it writes is checked value by value against the findings it cites, and any sentence
containing something that is not in those findings is removed and listed for you in `REVIEW.md`.

Everything is a **draft for your review**. Spoor reports what the records say; it does not decide
who did what.

[![tests](https://github.com/TastyT0rtuga/spoor/actions/workflows/ci.yml/badge.svg)](https://github.com/TastyT0rtuga/spoor/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-green)

> **Repository vs. release.** This repository holds the source, tests, fictional demo returns and
> build scripts. The thing you run on an examination machine is the release ZIP
> (`Spoor-<version>.zip` + `SHA256SUMS.txt`), which also carries an embedded Python for Windows, the
> pinned libraries and the offline DB-IP network data — see [Building the package](#14-building-the-package-from-this-repository).
> On Linux/WSL/macOS with Python 3.10+ you can run straight from a checkout:
> `pip install -r requirements.txt && ./spoor.sh selftest`.
>
> Spoor is a personal open-source project and is not an official product of, or endorsed by, any
> agency. Nothing in it is legal advice; every output is a draft for a qualified examiner's review.

---

## 1. First use on the sandbox (5 minutes)

1. Copy `Spoor-1.0.0.zip` and `SHA256SUMS.txt` to the sandbox and check the ZIP arrived intact.
   In PowerShell, in that folder, this must print `True`:

   ```
   (Get-FileHash .\Spoor-1.0.0.zip -Algorithm SHA256).Hash -eq (Get-Content .\SHA256SUMS.txt).Split(' ')[0]
   ```

   If the ZIP passed through an internet-connected machine, also run `Unblock-File .\Spoor-1.0.0.zip`
   (or right-click it → Properties → Unblock) so Windows does not show security prompts for every
   file inside. Then unzip it to a short path, e.g. `C:\Spoor` (short paths avoid Windows'
   260-character limit when ZIP returns are extracted).
2. Double-click **`SELFTEST.bat`**. It runs the whole pipeline on fictional demo returns in a
   temporary folder and should end with `ALL GOOD` (about 10 seconds). It also checks every program
   file against `PROGRAM.sha256`, so you can show the program was not altered after it was
   packaged. Run it again after any change to the machine.
3. Double-click **`Spoor.bat`**. A console window opens and your browser opens the dashboard.
   Keep that window open while you use the dashboard. Closing it does **not** stop an analysis
   that is already running.

To try it before using real returns: on the home page click **Try it on fictional demo data**.

## 2. Analysing a set of returns

1. **New case** → give it a name, your name, and the local time zone you want times shown in
   (everything is computed in UTC; the local zone is only for display).
2. **Sources** → paste the path of the folder (or file, or ZIP) holding the returns, or use
   **Browse…** → **Add**. Encrypted ZIP? Enter its password first. (AES-encrypted ZIPs must be
   extracted with 7-Zip and the folder added instead.)
3. **Run analysis.** Leave *AI-drafted summary* ticked if a local model is installed (section 5).
4. Watch the trail across the top of the case: Hash → Map → Read → Index → Analyse → Report →
   Verify → AI draft → Final. The report is written as soon as *Analyse* finishes, before the
   slow AI stage, so you can start reading while the model works.
5. **Check how each file was read** (Sources → click a file). Spoor shows the time zone it used and
   why, the day/month order, the account it attributed rows to, and which column it read as what.
   Change anything that is wrong, press **Preview how it will be read**, then **Save settings** and
   **Run again** — only the changed files are re-read.
6. Read **Reports → Report**, then work through **Review checklist**.

Click any citation (e.g. `S10:L505`) in the dashboard to open that place in the original file,
read fresh from disk, with the cited line highlighted.

## 3. Checking progress on long runs

Spoor is built to grind through very large returns over hours or days:

| Where | What you see |
|---|---|
| Dashboard | The stage trail, percentage, amount read, speed and time left in the current stage. Refreshes every 3 s. |
| `PROGRESS.md` in the case folder | The same status, rewritten every 15 seconds, readable in Notepad from anywhere on the machine. |
| `spoor-cli status "Case name" --watch` | The same status in a console, refreshed every 10 s. |
| `logs\run.log` in the case folder | Every step, with stage durations. |

The analysis runs in its own background process at below-normal priority (the machine stays usable)
and asks Windows not to sleep while it works. If the computer restarts, or you press **Stop**,
press **Resume analysis**: reading continues from the last checkpoint (byte offset / row / page),
finished stages are kept, and AI sections already drafted are reused. A resumed run produces
exactly the same records and findings as an uninterrupted one (this is tested).

Set the Windows power plan to *never sleep when plugged in* if policy allows; Windows Update
restarts will still interrupt a run — just resume.

## 4. What you get

Everything is in `cases\<case>\report\`:

| File | Contents |
|---|---|
| `REPORT.md` | Start here. Case summary, the verified AI summary (if any), priority-1 findings, every category with charts. |
| `FINDINGS.md` | Every finding (F001…): statement, tables, evidence citations and the read-only SQL that reproduces it. |
| `EVIDENCE.md` | The records behind each finding, quoted verbatim from the original files. |
| `SOURCES.md` | Every file: path, size, SHA-256, format, encoding, time zone and its basis, column mapping, parse statistics. |
| `TIMELINE.md` | Activity in time order, in UTC and your local zone. |
| `REVIEW.md` | Tick-box checklist: every assumption, anything not analysed, priority-1 findings to confirm, AI sentences removed or flagged. |
| `METHODS.md` | Exactly how each analysis works, its parameters, data sources and limitations — for your report or testimony prep. |
| `CITATION_CHECK.md` | The result of re-reading every cited record from the original files after the analysis. |
| `exports\*.csv` | Full timeline, IP inventory, **IP/timestamp/port list for follow-on legal process**, link-chart edges/nodes for i2 or Gephi, identifiers, accounts, counterparties. |
| `questions\Q###.md`, `lookups\L###.md` | Saved answers from Ask and Look up. |
| `MANIFEST.sha256` | SHA-256 of every file in the report folder. |

**Citation formats.** `S03:L1842` = source S03 (listed in SOURCES.md), line 1842 of the file.
`S05:Logins!R220` = worksheet *Logins*, row 220. `S07:p2:L14` = PDF page 2, line 14 of the
extracted text. `S08:L120:C17` = HTML file line 120, column 17. `S03:$.login_history[17]` = JSON
path. `L120+L122` = lines read together (see proximity pairing, below).

## 5. The local model (optional)

Spoor talks to a model server on this machine only (default `http://127.0.0.1:11434`, Ollama).
Without one, everything except the AI summary and Ask works.

**If the Gumshoe transfer bundle is already installed on the sandbox**, Ollama and the models are
already there — start Ollama (`C:\DFIR\ollama-pcores.cmd`) and Spoor finds it.

Otherwise, on an internet-connected Windows machine:

1. Install Ollama (ollama.com), then run `ollama pull qwen2.5:7b-instruct`
   (optional, faster/smaller: `ollama pull qwen2.5:3b-instruct`).
2. Copy `OllamaSetup.exe` and the folder `%USERPROFILE%\.ollama\models` to the transfer drive.
3. On the sandbox: run `OllamaSetup.exe`, copy the `models` folder to `%USERPROFILE%\.ollama\`,
   start Ollama.
4. In Spoor: **Settings → Local model → Save and test.** *Choose automatically* picks the best
   installed model from a list of known-good ones (Qwen 2.5 7B first).

On the i7-12700 / 16 GB OptiPlex, a 7B model drafts one summary section in roughly 2–5 minutes;
a question takes 1–3 minutes. The model only ever sees findings or query results, never the raw
returns. Set **CPU threads** to 8 (the P-cores).

**How the AI is kept honest:**
- *Summary sentences* must cite findings. A sentence is removed if any IP, email, phone, crypto
  address, MAC, URL, timestamp, date, time, number, percentage, ASN, source label, capitalised name
  or account name in it is not in the findings it cites (rounded numbers only after words like
  "about", and never more than the stated precision). Sentences with nothing checkable in them are
  removed. Inference ("likely", "suggests", "appears to"…) and characterisation ("attacker",
  "compromised", "fraud"…) are kept but marked ⚑ for your judgment. Removed sentences and the reason
  for each are in `REVIEW.md`.
- *Ask* questions: the model writes one SQL query; it runs on a read-only connection with an
  authoriser that blocks everything except reading. The answer shown **is the query result**, with
  citations, and the query is shown so you can check or re-run it.
- The verifier checks values, not meaning: a sentence can still pair true values misleadingly. When
  values come from different rows of a finding, the sentence is flagged. Read the summary as a draft.

## 6. What the analyses do

| Area | Findings |
|---|---|
| Sources & data quality | per-file counts and time range; how times were interpreted; every assumption (time zone, day/month order, DST); unparseable values; PDF pages with no text; duplicate files; overlapping returns |
| IP addresses | inventory; IPs in several sources or used by several accounts, with the closest records of two accounts on the same IP; private/CGNAT addresses; which events carry a source port; networks (ASN) and countries from the bundled offline DB-IP data; hosting/VPN-named networks; subnet clusters; **the IP/timestamp/port list for follow-on process** |
| Logins & security | per-account totals, IPs and user agents; failed-login bursts and the successful login that followed; IPs failing against 3+ accounts; password/2FA/recovery/e-mail changes made from an IP the account had just started using |
| Timing | hour-of-day and weekday profile in UTC and local time, quietest window, busiest days, inactivity gaps, rapid switches between networks or countries |
| Links | accounts connected by shared IPs (with the closest co-use as evidence and a Mermaid diagram); emails, phones, crypto addresses and devices shared across accounts or sources; link-chart CSVs |
| Identifiers | every email, phone, Bitcoin/Ethereum/TRON/Litecoin/Dogecoin/Monero address, MAC, IMEI and URL, kept only when its checksum verifies (Base58Check, Bech32/Bech32m, EIP-55, Luhn) |
| Counterparties | most frequent counterparties per account; largest amounts (totals only within one currency) |
| Watchlists | hits against your own lists of IPs, ranges and identifiers (format in `watchlists\README.txt`; README files are not read as lists) |

Thresholds (burst size, gap length, windows…) are under **Settings → Analysis settings** and are
recorded in each case's `METHODS.md`.

**Look up** (no AI) shows everything about an IP or CIDR range, an account, an identifier, any text,
or a time window, with citations, and saves it as Markdown.

## 7. Time zones — the most common source of error

- A timestamp with its own offset (`Z`, `+02:00`, `UTC`, `PST`, an IANA zone) is converted with it.
- Otherwise the file's zone applies. Spoor reads it from the header (`Time (UTC)`), the lines above
  the data (`All times are Pacific`) or the file name, and says where it found it. If nothing
  indicates a zone, it uses UTC **and flags it as a priority-1 assumption** — check the provider's
  cover letter and set the right zone under Sources.
- Daylight saving: times in the repeated autumn hour are flagged `ambiguous_dst`; times in the
  skipped spring hour are flagged `nonexistent_local_time`; "PST" used in summer is flagged
  `abbr_dst_mismatch`. A header saying "PST" is read as Pacific time *with* DST — if the provider
  means a fixed UTC−8 all year, set the zone to `UTC-08:00`.
- Numeric dates: day/month order is proven from the data when a value is above 12; otherwise
  MM/DD is assumed and flagged.
- Date-only values keep their calendar date; no time is invented.

## 8. Formats

CSV/TSV/pipe/semicolon (any encoding, including Cyrillic cp1251 and UTF-16), Excel `.xlsx/.xlsm/.xls`
(all sheets, hidden ones too), JSON and JSON Lines (huge top-level arrays are streamed), HTML (data
tables, and key/value layouts such as some providers' records pages), PDF (text extracted per page;
**scanned pages are listed as not analysed — no OCR**), plain text and logs (Apache/Nginx, mbox),
and ZIP (extracted into the case folder; each member hashed and cited separately).

*Proximity pairing:* in free text where an IP and its time sit on different lines (HTML key/value
pages), an IP line is paired with the nearest timestamp line within 6 lines, never across another
IP line. Such records cite every line used and are flagged `paired_by_proximity` for review.

## 9. Command line

`spoor-cli.bat` (Windows) or `./spoor.sh` (Linux/WSL, needs Python 3.10+):

```
spoor-cli new "Case name" --examiner "SA ..." --tz America/New_York
spoor-cli add "Case name" D:\Returns\Google
spoor-cli run "Case name"            (background; add --no-llm, --wait, --accounts N)
spoor-cli status "Case name" --watch
spoor-cli cancel "Case name"
spoor-cli lookup "Case name" --ip 198.51.100.0/24 --from 2024-04-01 --to 2024-04-30
spoor-cli ask "Case name" "Which IPs logged in to x@example.com in April 2024?"
spoor-cli report "Case name"         (rewrite the Markdown from current results)
spoor-cli selftest
```

## 10. Space and speed

Measured on a test container (the OptiPlex should be similar or faster): about **8,000 records per
second** read; a 400,000-row login log took under 2 minutes end to end (no AI). The case database
is roughly **5–6× the size of the text returns** (it keeps the verbatim text of every record plus a
full-text index; turn off *fts* in Analysis settings to save ~10%). A 10 GB return set therefore
needs about 60 GB free. Records are streamed rather than loaded into memory (about 0.4 GB peak in
the 400,000-row test), which leaves room for the model on a 16 GB machine.

## 11. Air-gap and security notes

- No component makes an outbound connection. The only network call in the code is to the local model
  server address in Settings (`llm.py`; system proxy settings are ignored). Fonts, Python, libraries
  and the ASN/country data are all in this folder.
- The dashboard listens on 127.0.0.1 only and requires a per-launch token (the link Spoor opens),
  checks the Host header and refuses cross-site requests.
- Source files are opened read-only and never modified; each is hashed before reading and re-hashed
  after the analysis (`CITATION_CHECK.md`, `SOURCES.md`). Every action (files added, mappings changed,
  jobs, AI calls) is logged in `logs\audit.log` and the case database, including the full prompts and
  replies of every model call.

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| Browser shows "Open Spoor from its window" | Use the link printed in the Spoor console window (each launch makes a new one). |
| "No local model" in the top bar | Start Ollama, then Settings → Save and test. The analysis still runs without it. |
| A file shows `error` | Click it: the message says why (encrypted ZIP, unreadable file…). Fix and Run again. |
| Times are off by hours | Sources → the file → set the right time zone (see section 7) → Save → Run again. |
| Wrong column read as the IP/time/account | Sources → the file → change "Read as" → Preview → Save → Run again. |
| Job shows *interrupted* | The computer restarted or the worker stopped; press Resume analysis. |
| "Windows protected your PC" or a security warning when starting a `.bat` | The files carry Windows' downloaded-from-internet mark. Delete the extracted folder, run `Unblock-File` on the ZIP (section 1) and extract again. |
| `SELFTEST.bat` reports files that do not match `PROGRAM.sha256` | The program folder was changed after packaging (or extracted incompletely). Extract a fresh copy from the verified ZIP. |
| Disk filling up | Stop, free space (the case folder can be moved to a larger drive with Spoor closed), Resume. |

## 13. Folder layout

```
Spoor\
  Spoor.bat  SELFTEST.bat  spoor-cli.bat  spoor.sh
  PROGRAM.sha256    SHA-256 of every program file (checked by SELFTEST.bat)
  app\spoor\        the program (Python)
  runtime\python\   Python 3.13 for Windows (embeddable, unmodified except its ._pth path file)
  vendor\           openpyxl, xlrd, pypdf, tzdata, maxminddb
  geoip\            offline ASN and country data (DB-IP Lite, CC BY 4.0)
  watchlists\       optional lists checked in every case
  demo\returns\     fictional returns used by the self-test and the demo case
  cases\            your cases (created on first use)
  tests\            developer tests (python tests\run_tests.py)
  LICENSES\         third-party licenses
  build\            (repository only) fetch_deps.py, package.py, requirements-vendor.txt
```

In the repository, `runtime\`, `vendor\`, the `geoip\*.mmdb` files and `PROGRAM.sha256` are not
committed; `build\fetch_deps.py` and `build\package.py` produce them.

## 14. Building the package from this repository

On an internet-connected machine with Python 3.10+ (any OS — the result is the Windows package):

```
python build/fetch_deps.py      # Python 3.13.16 embeddable (SHA-256 pinned), the pinned wheels
                                # (hash-checked, build/requirements-vendor.txt), DB-IP Lite for this month
python build/package.py         # PROGRAM.sha256 + dist/Spoor-<version>.zip + dist/SHA256SUMS.txt
```

`fetch_deps.py --no-geoip` skips the network data (then follow `geoip/README.txt`). The build is
reproducible: the runtime, vendored libraries and DB-IP files it fetches are byte-identical to the
ones in the 1.0.0 release, and CI builds the package on every push. Tests: `python tests/run_tests.py`
(units, the 51-check self-test, dashboard/API and security checks; no Windows needed).

Spoor 1.0.0. Third-party components and their licenses: `LICENSES/THIRD-PARTY.txt`. Spoor itself is
Apache-2.0 (`LICENSE`). A companion tool for server images, [Gumshoe](https://github.com/TastyT0rtuga/gumshoe),
shares the same local-model setup.
