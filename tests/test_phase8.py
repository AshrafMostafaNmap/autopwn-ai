"""Phase-8 tests: the audit log + authorization acknowledgement (security).

Covers the tamper-evident hash chain, the ack entry, resume, and detection of
alteration/removal — the integrity guarantees behind the full-trust model.
"""
from __future__ import annotations

import json

from autopwn.govern import Acknowledgement, AuditLog


def test_ack_is_first_entry_and_chain_verifies(tmp_path):
    log = AuditLog.open(tmp_path / "audit.jsonl")
    log.acknowledge(Acknowledgement(operator="alice", in_scope=["app.lab"],
                                    authorized=True, profile="safe"))
    log.record("run.start", goal="assess app.lab")
    log.record("finding.verified", id="AP-1", severity="critical")
    assert len(log) == 3
    assert AuditLog.verify(tmp_path / "audit.jsonl") is True
    first = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert first["action"] == "authorization"
    assert first["ack"]["operator"] == "alice" and first["ack"]["authorized"] is True


def test_chain_links_prev_hash(tmp_path):
    log = AuditLog.open(tmp_path / "a.jsonl")
    log.record("one"); log.record("two")
    lines = [json.loads(line) for line in (tmp_path / "a.jsonl").read_text().splitlines()]
    assert lines[0]["prev"] == "0" * 64
    assert lines[1]["prev"] == lines[0]["hash"]          # chained


def test_tampering_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog.open(p)
    log.record("run.start", goal="x")
    log.record("finding.verified", id="AP-1", severity="high")
    assert AuditLog.verify(p) is True
    # alter a recorded field without fixing the hash → must fail verification
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1]); rec["severity"] = "low"
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    assert AuditLog.verify(p) is False


def test_removal_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog.open(p)
    log.record("a"); log.record("b"); log.record("c")
    lines = p.read_text().splitlines()
    del lines[1]                                          # drop the middle entry
    p.write_text("\n".join(lines) + "\n")
    assert AuditLog.verify(p) is False


def test_resume_continues_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog.open(p)
    log.record("first")
    # reopen (e.g. a resumed run) and append — the chain must stay valid
    log2 = AuditLog.open(p)
    assert len(log2) == 1
    log2.record("second")
    assert AuditLog.verify(p) is True
    assert len(log2) == 2
