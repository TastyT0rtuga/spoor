# Security

Spoor is built to run on an isolated examination workstation. Its security properties, as
designed:

* **No outbound connections.** The only network call in the code base is to the local model
  server address configured in Settings (`app/spoor/llm.py`, default `http://127.0.0.1:11434`),
  and system proxy settings are ignored for it. Fonts, libraries and the ASN/country data ship in
  the package.
* **Local dashboard only.** The web server binds 127.0.0.1, requires a per-launch token, checks the
  `Host` header and refuses cross-site requests. `tests/run_tests.py` exercises these checks.
* **Returns are read-only.** Source files are opened read-only, hashed before reading and re-hashed
  after the analysis (`SOURCES.md`, `CITATION_CHECK.md`).
* **The model cannot change data.** Natural-language questions run as one SQL query on a read-only
  connection with an authoriser that permits reading only.
* **Tamper evidence.** `SELFTEST.bat` checks every program file against `PROGRAM.sha256`, written
  at packaging time; the release ZIP ships with `SHA256SUMS.txt`.

## Reporting a vulnerability

Open a GitHub issue for anything that is not sensitive. For a vulnerability that could expose return
data or let the model or a web page act on the machine, use GitHub's private vulnerability reporting
on this repository instead of a public issue. Please include the Spoor version (`app/spoor/__init__.py`),
the operating system, and a minimal reproduction — fictional data only, never real returns.

## Scope notes

* Spoor processes untrusted files (legal-process returns). Readers are bounded and streamed, but a
  malformed file that crashes a reader is a bug worth reporting even without a security impact.
* The dashboard trusts the local user; it is not designed to be exposed on a network.
