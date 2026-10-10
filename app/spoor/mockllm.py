"""A stand-in for Ollama used by the self-test (and the developer tests). It answers like a sloppy model on purpose: some sentences are
copied from the findings (should pass), some contain invented values (must be rejected), some
use inference words (must be flagged). SQL requests get a valid query, or a forbidden one first."""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CALLS = []


def _sentences_for(findings: list[dict], retry: bool) -> list[dict]:
    out = []
    for f in findings[:3]:
        first = re.split(r"(?<=[.])\s+(?=[A-Z])", f["statement"])[0]
        out.append({"text": first, "cites": [f["id"]]})
    if not retry and findings:
        fid = findings[0]["id"]
        out.append({"text": "IP 8.8.8.8 was used 999 times by the attacker.", "cites": [fid]})
        out.append({"text": "The account was probably accessed from Tor exit nodes.", "cites": [fid]})
        out.append({"text": f"See also the finding that does not exist.", "cites": ["F999"]})
        v = findings[0].get("values") or {}
        num = next((val for val in v.values() if isinstance(val, int) and val > 2), None)
        if num is not None:
            out.append({"text": f"{findings[0]['title']} likely involves {num} records.", "cites": [fid]})
    return out


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send({"models": [{"name": "qwen2.5:7b-instruct", "digest": "sha256:0000mock"}]})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        CALLS.append(req)
        msgs = req.get("messages", [])
        sys_ = msgs[0]["content"] if msgs else ""
        last = msgs[-1]["content"] if msgs else ""
        if "investigator's analysis report" in sys_:
            first_user = next(m["content"] for m in msgs if m["role"] == "user")
            fj = first_user.split("Findings (JSON):", 1)[1].strip()
            findings = json.loads(fj)
            retry = "failed automatic verification" in last
            content = json.dumps({"sentences": _sentences_for(findings, retry)})
        elif "Write ONE SQLite SELECT" in sys_:
            q = last
            if "That query failed" in q:
                sql = "SELECT cite, ts_utc, account, category FROM ev WHERE ip = '159.89.214.31' ORDER BY ts_utc LIMIT 500"
            elif "delete" in q.lower():
                sql = "DELETE FROM events"
            elif "159.89" in q:
                sql = "SELECT cite, ts_utc, account, category, action FROM ev WHERE ip = '159.89.214.31' ORDER BY ts_utc LIMIT 500"
            else:
                sql = "SELECT ip, COUNT(*) AS n, MIN(cite) AS example_cite FROM ev WHERE ip IS NOT NULL GROUP BY ip ORDER BY n DESC LIMIT 10"
            content = json.dumps({"sql": sql, "explanation": "mock"})
        elif "summarise SQL query results" in sys_:
            rows = json.loads(last.split(":\n", 1)[1])
            r1 = rows[0]
            vals = [v for k, v in r1.items() if k != "row"]
            good = f"The first row lists {vals[0]} at {vals[1]}." if len(vals) > 1 else f"The first row lists {vals[0]}."
            content = json.dumps({"sentences": [{"text": good, "cites": ["R1"]},
                                                {"text": "There were 424242 events from Russia.", "cites": ["R1"]}]})
        else:
            content = json.dumps({"sentences": []})
        self._send({"model": req.get("model"), "message": {"role": "assistant", "content": content}, "done": True})


def start(port: int = 11435) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
