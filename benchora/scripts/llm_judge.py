#!/usr/bin/env python3
"""llm_judge.py — LLM-as-judge for semantic TP/Unmatched/FN matching in Benchora.

Uses Haiku 4.5 via the LiteLLM proxy to judge whether a found vulnerability
or endpoint matches a ground-truth entry.  Self-consistency voting (N=3),
disk caching, graceful fallback when the LLM is unreachable.

Auth: reads ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN (OAuth) or
ANTHROPIC_API_KEY from the environment — same proxy Claude Code uses.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter

_DEFAULT_MODEL = "claude-haiku-4-5"
_API_VERSION = "2023-06-01"
_TIMEOUT_S = 30.0
_MAX_TOKENS = 256
_PROMPT_VERSION = "v1"

_CLAUDE_CODE_SPOOF = "You are Claude Code, Anthropic's official CLI for Claude."

_VULN_SYSTEM = (
    "You are a security vulnerability matching judge. You receive a FOUND vulnerability "
    "from an automated scanner and a GROUND TRUTH vulnerability. Decide whether they describe "
    "the SAME specific security issue — same root cause, same affected endpoint/component.\n\n"
    "Guidelines:\n"
    "- Same CWE family + same or overlapping endpoint = likely match\n"
    "- Same endpoint but fundamentally different vulnerability types = NOT a match\n"
    "- Different endpoints = likely NOT a match even if same vuln type (e.g. two separate "
    "SQL injections on different endpoints are different findings)\n"
    "- Titles/descriptions may use different words for the same issue — focus on the "
    "underlying security flaw, not the wording\n"
    "- CWE numbers may differ for the same root cause (e.g. CWE-915 mass assignment and "
    "CWE-269 privilege escalation can describe the same issue)\n\n"
    "Respond with ONLY a JSON object: {\"match\": true|false, \"confidence\": 0.0-1.0, "
    "\"reasoning\": \"one sentence\"}"
)

_ENDPOINT_SYSTEM = (
    "You are an API endpoint matching judge. You receive a FOUND endpoint from a web crawler "
    "and a GROUND TRUTH endpoint. Decide whether they refer to the same API endpoint.\n\n"
    "Guidelines:\n"
    "- Path normalization: /api/patients/123/ and /api/patients/{id}/ are the same\n"
    "- Trailing slashes don't matter: /api/health and /api/health/ are the same\n"
    "- HTTP method differences: GET and HEAD on the same path are the same endpoint\n"
    "- Subpaths are NOT the same: /api/patients/ and /api/patients/{id}/records/ are different\n"
    "- Query parameters don't change the endpoint identity\n\n"
    "Respond with ONLY a JSON object: {\"match\": true|false, \"confidence\": 0.0-1.0, "
    "\"reasoning\": \"one sentence\"}"
)


def _extract_json(text: str):
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    depth = start = 0
    for i, ch in enumerate(t):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(t[start:i + 1])
                except Exception:
                    continue
    return None


class LLMJudge:
    def __init__(self, model: str = _DEFAULT_MODEL, cache_dir: str | None = None,
                 n_votes: int = 1, quiet: bool = False):
        self.model = model
        self.n_votes = max(1, n_votes)
        self._quiet = quiet
        self._calls = 0

        base = os.environ.get("ANTHROPIC_BASE_URL", "").rstrip("/")
        token = os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        if not base:
            self.available = False
            self._reason = "ANTHROPIC_BASE_URL not set"
            return
        if not token and not api_key:
            self.available = False
            self._reason = "no credentials (ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY unset)"
            return

        self._base = base
        self._headers = {"anthropic-version": _API_VERSION, "content-type": "application/json"}
        if token:
            self._headers["authorization"] = "Bearer " + token
            self._headers["anthropic-beta"] = "oauth-2025-04-20"
            self._system_prefix = _CLAUDE_CODE_SPOOF + "\n\n"
        else:
            self._headers["x-api-key"] = api_key
            self._system_prefix = ""

        self._cache_path = os.path.join(cache_dir, ".llm_judge_cache.json") if cache_dir else None
        self._cache: dict[str, dict] = {}
        if self._cache_path and os.path.exists(self._cache_path):
            try:
                with open(self._cache_path, encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

        self.available = self._ping()
        if not self.available:
            self._reason = f"connectivity check failed ({self.model} at {self._base})"

    def _ping(self) -> bool:
        try:
            import httpx
        except ImportError:
            return False
        try:
            resp = httpx.post(
                self._base + "/v1/messages",
                headers=self._headers,
                json={
                    "model": self.model,
                    "max_tokens": 8,
                    "system": self._system_prefix + "Reply with OK.",
                    "messages": [{"role": "user", "content": "ping"}],
                },
                timeout=15.0,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def _call_api(self, system: str, user_prompt: str) -> dict | None:
        try:
            import httpx
        except ImportError:
            return None
        body = {
            "model": self.model,
            "max_tokens": _MAX_TOKENS,
            "system": self._system_prefix + system,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        try:
            resp = httpx.post(
                self._base + "/v1/messages",
                headers=self._headers,
                json=body,
                timeout=_TIMEOUT_S,
            )
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except Exception:
            return None
        if data.get("stop_reason") == "refusal":
            return None
        text = ""
        for block in data.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text":
                text += block.get("text", "")
        self._calls += 1
        return _extract_json(text)

    def _cache_key(self, *parts: str) -> str:
        blob = "|".join([self.model, _PROMPT_VERSION] + list(parts))
        return hashlib.sha256(blob.encode()).hexdigest()[:24]

    def _save_cache(self):
        if not self._cache_path:
            return
        try:
            os.makedirs(os.path.dirname(self._cache_path), exist_ok=True)
            with open(self._cache_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
        except Exception:
            pass

    def _vote(self, system: str, prompt: str, ck: str) -> dict | None:
        if ck in self._cache:
            return self._cache[ck]
        raw: list[dict] = []
        for _ in range(self.n_votes):
            v = self._call_api(system, prompt)
            if isinstance(v, dict) and "match" in v:
                raw.append(v)
        if not raw:
            return None
        matches = [bool(v["match"]) for v in raw]
        winner = sum(matches) > len(matches) / 2
        confs = []
        for v in raw:
            if bool(v["match"]) == winner:
                c = v.get("confidence")
                if isinstance(c, (int, float)) and not isinstance(c, bool):
                    confs.append(min(1.0, max(0.0, float(c))))
        if confs:
            conf = round(sum(confs) / len(confs), 3)
        else:
            freq = sum(1 for m in matches if m == winner) / len(matches)
            conf = round(freq, 3)
        reasons = [str(v.get("reasoning", "")) for v in raw
                    if bool(v["match"]) == winner and v.get("reasoning")]
        result = {
            "match": winner,
            "confidence": conf,
            "reasoning": reasons[0] if reasons else "",
            "n_votes": len(raw),
        }
        self._cache[ck] = result
        self._save_cache()
        return result

    @property
    def calls_made(self) -> int:
        return self._calls

    def _extract_finding_endpoint(self, finding: dict) -> str:
        endpoint = finding.get("endpoint") or ""
        if isinstance(endpoint, list):
            endpoint = endpoint[0] if endpoint else ""
        if not endpoint:
            aff = finding.get("affected_endpoints")
            if isinstance(aff, dict):
                endpoint = aff.get("target") or aff.get("url") or ""
            elif isinstance(aff, list) and aff:
                endpoint = (aff[0] if isinstance(aff[0], str)
                            else (aff[0].get("url") or aff[0].get("target") or ""))
        if not endpoint:
            endpoint = finding.get("target") or ""
        if " and " in endpoint:
            endpoint = endpoint.split(" and ")[0].strip()
        return endpoint

    def judge_vuln_match(self, finding: dict, gt_vuln: dict) -> dict | None:
        if not self.available:
            return None

        f_cwe = finding.get("cwe", "")
        if isinstance(f_cwe, list):
            f_cwe = f_cwe[0] if f_cwe else ""
        f_endpoint = self._extract_finding_endpoint(finding)
        f_title = (finding.get("title") or finding.get("vulnerability") or "")[:200]
        f_summary = (finding.get("summary") or finding.get("description") or "")[:300]
        f_type = finding.get("test_type") or finding.get("vuln_class") or ""

        gt_id = gt_vuln.get("id", "")
        gt_title = (gt_vuln.get("title") or "")[:200]
        ae = gt_vuln.get("affected_endpoint", "")
        gt_method = gt_vuln.get("method") or (ae.split(" ")[0] if " " in ae else "")
        gt_endpoint = gt_vuln.get("endpoint") or (ae.split(" ", 1)[-1].strip() if ae else "")
        gt_cwe = gt_vuln.get("cwe_primary") or ""
        if not gt_cwe:
            raw = gt_vuln.get("cwe", "")
            gt_cwe = raw[0] if isinstance(raw, list) and raw else (raw if isinstance(raw, str) else "")
        gt_class = gt_vuln.get("vuln_class", "")
        gt_desc = (gt_vuln.get("description") or "")[:300]

        prompt = (
            f"FOUND VULNERABILITY:\n"
            f"  Title: {f_title}\n"
            f"  CWE: {f_cwe}\n"
            f"  Endpoint: {f_endpoint}\n"
            f"  Type: {f_type}\n"
            f"  Summary: {f_summary}\n\n"
            f"GROUND TRUTH VULNERABILITY:\n"
            f"  ID: {gt_id}\n"
            f"  Title: {gt_title}\n"
            f"  CWE: {gt_cwe}\n"
            f"  Endpoint: {gt_method} {gt_endpoint}\n"
            f"  Vuln Class: {gt_class}\n"
            f"  Description: {gt_desc}"
        )

        ck = self._cache_key("vuln", f_title, f_cwe, f_endpoint, gt_id)
        return self._vote(_VULN_SYSTEM, prompt, ck)

    def judge_endpoint_match(self, found_key: str, gt_key: str,
                             found_meta: dict | None = None,
                             gt_meta: dict | None = None) -> dict | None:
        if not self.available:
            return None

        f_desc = (found_meta or {}).get("description", "")
        gt_desc = (gt_meta or {}).get("description", "")

        prompt = (
            f"FOUND ENDPOINT: {found_key}\n"
            f"GROUND TRUTH ENDPOINT: {gt_key}\n"
        )
        if f_desc:
            prompt += f"Found description: {f_desc}\n"
        if gt_desc:
            prompt += f"GT description: {gt_desc}\n"

        ck = self._cache_key("endpoint", found_key, gt_key)
        return self._vote(_ENDPOINT_SYSTEM, prompt, ck)
