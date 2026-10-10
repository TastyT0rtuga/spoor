"""Client for a LOCAL model server: Ollama (default, http://127.0.0.1:11434) or any
OpenAI-compatible server (llama.cpp server, LM Studio, vLLM). Standard library only; system
proxy settings are ignored so traffic never leaves the machine by accident."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Optional

from .config import PREFERRED_MODELS
from .util import utc_now_str

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_THINK = re.compile(r"<think>.*?</think>", re.S)


class LLMError(Exception):
    pass


class LLM:
    def __init__(self, cfg: dict, con=None, job_id: Optional[int] = None):
        self.cfg = cfg
        self.url = (cfg.get("url") or "http://127.0.0.1:11434").rstrip("/")
        self.provider = cfg.get("provider", "ollama")
        self.con = con
        self.job_id = job_id
        self._models = None
        self._digests: dict = {}

    # ------------------------------------------------------------------ http
    def _req(self, path: str, payload: Optional[dict] = None, timeout: float = 30):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json"})
        try:
            with _OPENER.open(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:500]
            raise LLMError(f"HTTP {e.code} from {self.url}{path}: {body}") from e
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise LLMError(f"cannot reach the model server at {self.url} ({e})") from e

    # ------------------------------------------------------------------ discovery
    def models(self) -> list[str]:
        if self._models is None:
            if self.provider == "ollama":
                d = self._req("/api/tags", timeout=10)
                self._models = [m["name"] for m in d.get("models", [])]
                self._digests = {m["name"]: m.get("digest", "") for m in d.get("models", [])}
            else:
                d = self._req("/v1/models", timeout=10)
                self._models = [m["id"] for m in d.get("data", [])]
        return self._models

    def status(self) -> dict:
        try:
            ms = self.models()
            return {"ok": True, "url": self.url, "provider": self.provider, "models": ms,
                    "model": self.resolve_model() if ms else None}
        except LLMError as e:
            return {"ok": False, "url": self.url, "provider": self.provider, "error": str(e), "models": []}

    def resolve_model(self, purpose: str = "narrative") -> str:
        want = self.cfg.get("sql_model") if purpose == "sql" and self.cfg.get("sql_model") else self.cfg.get("model", "auto")
        ms = self.models()
        if want and want != "auto":
            if want in ms or self.provider != "ollama":
                return want
            for m in ms:
                if m.startswith(want):
                    return m
            raise LLMError(f"model '{want}' is not installed on the model server (installed: {', '.join(ms) or 'none'})")
        for pref in PREFERRED_MODELS:
            for m in ms:
                if m == pref or m == pref + ":latest" or (":" not in pref and m.split(":")[0] == pref):
                    return m
        if ms:
            return [m for m in ms if "embed" not in m][0] if any("embed" not in m for m in ms) else ms[0]
        raise LLMError("no models are installed on the model server")

    def digest(self, model: str) -> str:
        if not self._digests and self.provider == "ollama":
            try:
                self.models()
            except LLMError:
                pass
        return self._digests.get(model, "")

    # ------------------------------------------------------------------ chat
    def chat(self, messages: list[dict], schema: Optional[dict] = None, purpose: str = "", model: Optional[str] = None) -> str:
        model = model or self.resolve_model("sql" if purpose.startswith("sql") else "narrative")
        opts = {"temperature": float(self.cfg.get("temperature", 0)), "seed": int(self.cfg.get("seed", 42)),
                "num_ctx": int(self.cfg.get("num_ctx", 8192))}
        if self.cfg.get("num_thread"):
            opts["num_thread"] = int(self.cfg["num_thread"])
        t0 = time.time()
        started = utc_now_str()
        text, err = "", None
        try:
            if self.provider == "ollama":
                payload = {"model": model, "messages": messages, "stream": False, "options": opts, "keep_alive": "30m"}
                if schema is not None:
                    payload["format"] = schema
                try:
                    d = self._req("/api/chat", payload, timeout=float(self.cfg.get("timeout_s", 3600)))
                except LLMError as e:
                    if schema is not None and "HTTP 4" in str(e):
                        payload["format"] = "json"   # older Ollama: JSON mode without a schema
                        d = self._req("/api/chat", payload, timeout=float(self.cfg.get("timeout_s", 3600)))
                    else:
                        raise
                text = (d.get("message") or {}).get("content", "")
            else:
                payload = {"model": model, "messages": messages, "temperature": opts["temperature"], "seed": opts["seed"],
                           "stream": False}
                if schema is not None:
                    payload["response_format"] = {"type": "json_object"}
                d = self._req("/v1/chat/completions", payload, timeout=float(self.cfg.get("timeout_s", 3600)))
                text = d["choices"][0]["message"]["content"]
            text = _THINK.sub("", text or "").strip()
            return text
        except LLMError as e:
            err = str(e)
            raise
        finally:
            if self.con is not None:
                try:
                    self.con.execute("INSERT INTO llm_calls(job_id, purpose, model, model_digest, options, prompt, response, started_at, "
                                     "seconds, ok, error) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                     (self.job_id, purpose, model, self.digest(model), json.dumps(opts),
                                      json.dumps(messages, ensure_ascii=False), text, started, round(time.time() - t0, 1),
                                      0 if err else 1, err))
                    self.con.commit()
                except Exception:  # noqa: BLE001
                    pass


def parse_json(text: str):
    """Tolerant JSON extraction from a model reply."""
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.S)
    try:
        return json.loads(t)
    except ValueError:
        pass
    m = re.search(r"\{.*\}", t, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except ValueError:
            pass
    raise LLMError("the model did not return valid JSON")
