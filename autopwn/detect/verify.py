"""Safe verification: confirm suspected findings without causing harm.

Methods: direct (the artifact is the proof), reflection (marker reflected
unencoded), boolean (true/false differential), time (one bounded delay),
protocol (read-only unauthenticated hello), manual (left suspected).
"""
from __future__ import annotations

import difflib
import socket
import time
import uuid
from urllib.parse import parse_qs, urlencode, urlparse

from .model import Candidate, VerifyResult


class SafeVerifier:
    """Runs non-destructive confirmations. Holds one HTTP client for the run."""

    def __init__(self, *, timeout: float = 15.0, time_threshold: float = 3.0):
        self.timeout = timeout
        self.time_threshold = time_threshold
        self._client = None

    def _http(self):
        if self._client is None:
            import httpx
            self._client = httpx.Client(follow_redirects=False, timeout=self.timeout,
                                        verify=False,
                                        headers={"User-Agent": "AutoPwn-Verify/0.1 (+purple-team)"})
        return self._client

    def _get(self, url: str, param: str | None = None, value: str | None = None):
        """GET `url`, optionally overriding one query param. Returns the response."""
        if param is not None:
            parsed = urlparse(url)
            qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            qs[param] = value
            url = parsed._replace(query=urlencode(qs)).geturl()
        return self._http().get(url)

    def verify(self, c: Candidate) -> VerifyResult:
        try:
            fn = getattr(self, f"_verify_{c.method}", None)
            if fn is None:
                return VerifyResult(False, c.method, note=f"no verifier for '{c.method}'")
            return fn(c)
        except Exception as e:
            return VerifyResult(False, c.method, note=f"verify error: {type(e).__name__}: {e}")

    def _verify_direct(self, c: Candidate) -> VerifyResult:
        # the detector already proved it (artifact present / header absent).
        return VerifyResult(True, "direct", note=c.note or "artifact confirmed at detection",
                            request=c.evidence_request, response=c.evidence_response,
                            steps=c.steps or ["observation is self-proving"])

    def _verify_reflection(self, c: Candidate) -> VerifyResult:
        marker = "apx" + uuid.uuid4().hex[:8]
        payload = f'{marker}"><svg/onload=1>'               # breaks out of attribute/tag
        resp = self._get(c.url, c.param, payload)
        body = resp.text or ""
        dangerous = f'{marker}"><svg/onload=1>'             # literal, unencoded
        encoded = marker + "&quot;&gt;"                      # entity-encoded form
        if dangerous in body and encoded not in body:
            return VerifyResult(True, "reflection",
                                note="marker reflected unencoded in HTML context",
                                request=f"GET {c.url} [{c.param}={payload}]",
                                response=_snippet(body, marker),
                                steps=["inject unique marker with tag-breakout",
                                       "marker reflected verbatim (not entity-encoded)"])
        return VerifyResult(False, "reflection",
                            note="marker not reflected unencoded (encoded or absent)")

    def _verify_boolean(self, c: Candidate) -> VerifyResult:
        base = c.vdata.get("base_value", "1")
        # string- and numeric-context tautology pairs (read-only)
        pairs = [
            (f"{base}' AND '1'='1", f"{base}' AND '1'='2"),
            (f"{base} AND 1=1", f"{base} AND 1=2"),
        ]
        baseline = (self._get(c.url, c.param, base).text or "")
        for true_p, false_p in pairs:
            t = self._get(c.url, c.param, true_p).text or ""
            f = self._get(c.url, c.param, false_p).text or ""
            sim_tb = _ratio(t, baseline)
            sim_fb = _ratio(f, baseline)
            # injectable iff TRUE tracks the baseline and FALSE diverges clearly
            if sim_tb >= 0.95 and sim_fb <= 0.85 and (sim_tb - sim_fb) >= 0.1:
                return VerifyResult(True, "boolean",
                                    note=f"boolean differential confirmed (true~{sim_tb:.2f}, false~{sim_fb:.2f})",
                                    request=f"GET {c.url} [{c.param}= TRUE vs FALSE]",
                                    response=_diff_snippet(t, f),
                                    steps=["send AND 1=1 (true) and AND 1=2 (false)",
                                           "true response matches baseline; false diverges"])
        return VerifyResult(False, "boolean", note="no stable boolean differential")

    def _verify_time(self, c: Candidate) -> VerifyResult:
        base = c.vdata.get("base_value", "1")
        delay = max(2, int(c.vdata.get("delay", self.time_threshold)))
        # a single, short, bounded delay — conservative blind check
        payload = f"{base}' AND (SELECT 1 FROM (SELECT SLEEP({delay}))x)-- -"
        baseline_t = _elapsed(lambda: self._get(c.url, c.param, base))
        delayed_t = _elapsed(lambda: self._get(c.url, c.param, payload))
        if delayed_t - baseline_t >= delay * 0.7:
            return VerifyResult(True, "time",
                                note=f"response delayed ~{delayed_t-baseline_t:.1f}s with SLEEP({delay})",
                                steps=[f"baseline {baseline_t:.1f}s vs delayed {delayed_t:.1f}s"])
        return VerifyResult(False, "time", note="no measurable time delay")

    def _verify_manual(self, c: Candidate) -> VerifyResult:
        # Cannot be confirmed safely/automatically — stays SUSPECTED by design.
        return VerifyResult(False, "manual",
                            note=c.note or "requires authorized manual verification")

    def _verify_protocol(self, c: Candidate) -> VerifyResult:
        host, port = c.host, int(c.vdata.get("port", 0))
        probe = c.vdata.get("probe", b"")                   # bytes to send (read-only hello)
        expect = c.vdata.get("expect", "")
        if not expect:                                      # no signature → cannot confirm
            return VerifyResult(False, "protocol", note="no confirmation signature")
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.settimeout(4)
                if probe:
                    s.sendall(probe)
                data = s.recv(512).decode("latin-1", "replace")
        except Exception as e:
            return VerifyResult(False, "protocol", note=f"connect failed: {e}")
        if expect.lower() in data.lower():
            return VerifyResult(True, "protocol",
                                note=f"unauthenticated {c.vdata.get('service','service')} responded",
                                response=_snippet(data, expect), steps=["read-only protocol hello, no auth"])
        return VerifyResult(False, "protocol", note="no unauthenticated response")

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a or "", b or "").ratio()

def _elapsed(fn) -> float:
    t0 = time.time()
    fn()
    return time.time() - t0

def _snippet(body: str, needle: str, width: int = 160) -> str:
    i = body.find(needle)
    if i < 0:
        return body[:width]
    start = max(0, i - width // 2)
    return body[start:start + width]

def _diff_snippet(a: str, b: str) -> str:
    return f"true-len={len(a)} false-len={len(b)}"
