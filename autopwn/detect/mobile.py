"""Static Android detectors over the APK inventory."""
from __future__ import annotations

from collections import Counter

from .model import Candidate


def detect_from_inventory(raw: dict, host: str) -> list[Candidate]:
    out: list[Candidate] = []
    flags = raw.get("flags", {}) or {}

    # hardcoded secrets (vaulted at recon) — the match is the proof
    kinds = raw.get("secret_kinds", []) or []
    if kinds:
        tally = ", ".join(f"{k}×{v}" for k, v in Counter(kinds).items())
        out.append(Candidate("mobile_secret", host=host, confidence=0.9, method="direct",
                             note=f"hardcoded secrets: {tally}",
                             evidence_response="(values vaulted locally)",
                             steps=["static scan of dex/resources", "secret pattern matched"]))

    if flags.get("cleartext"):
        out.append(Candidate("mobile_cleartext", host=host, confidence=0.85, method="direct",
                             note="usesCleartextTraffic present in manifest",
                             steps=["manifest references cleartext traffic"]))
    if flags.get("debuggable"):
        out.append(Candidate("mobile_debuggable", host=host, confidence=0.8, method="direct",
                             note="debuggable flag present in manifest",
                             steps=["manifest references debuggable"]))
    if flags.get("exported"):
        out.append(Candidate("mobile_exported", host=host, confidence=0.4, method="manual",
                             note="exported components present — needs per-component AXML review",
                             steps=["manifest has exported attributes; decode with apktool to confirm"]))
    return out
