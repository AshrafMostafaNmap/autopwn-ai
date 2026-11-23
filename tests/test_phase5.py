"""Phase-5 tests: cross-run memory, knowledge base, and memory-aware compaction.

DoD: a re-scan references the first run (new/fixed/reopened deltas); long runs
stay bounded (compaction holds a working summary + findings index, details in the
store); target data is encrypted at rest.
"""
from __future__ import annotations

from cryptography.fernet import Fernet

from autopwn.core.findings import Finding, Severity, SeverityInfo, Status, Target
from autopwn.memory import KnowledgeBase, TargetMemory


def _mem(tmp_path):
    return TargetMemory.open(tmp_path / "mem.db", key=Fernet.generate_key())


def _finding(fid, title="SQL Injection", score=9.8, status=Status.VERIFIED):
    return Finding(id=fid, title=title, target=Target(host="app.lab", url="http://app.lab/x"),
                   severity=SeverityInfo(cvss_score=score, rating=Severity.from_cvss(score)),
                   status=status)


def test_memory_kv_roundtrip_and_encrypted_at_rest(tmp_path):
    key = Fernet.generate_key()
    m = TargetMemory.open(tmp_path / "m.db", key=key)
    m.remember("app.lab", "stack", {"server": "nginx", "lang": "php"}, run_id="r1")
    assert m.recall("app.lab", "stack")["server"] == "nginx"
    m.close()
    # raw bytes on disk must not contain the plaintext
    raw = (tmp_path / "m.db").read_bytes()
    assert b"nginx" not in raw
    # reopening with the same key recovers the value (cross-run persistence)
    m2 = TargetMemory.open(tmp_path / "m.db", key=key)
    assert m2.recall("app.lab", "stack")["lang"] == "php"
    m2.close()

def test_memory_key_file_generated_and_reused(tmp_path):
    db = tmp_path / "sub" / "m.db"
    m = TargetMemory.open(db)                       # no key → generates key file
    m.remember("h", "k", "v")
    m.close()
    assert (db.parent / "memory.key").is_file()
    m2 = TargetMemory.open(db)                      # reuses the key file
    assert m2.recall("h", "k") == "v"
    m2.close()


def test_findings_delta_new_fixed_reopened(tmp_path):
    m = _mem(tmp_path)
    # run 1: two findings
    d1 = m.record_findings("app.lab", [_finding("F1"), _finding("F2")], run_id="r1")
    assert set(d1.new) == {"F1", "F2"} and not d1.fixed
    # run 2: F1 persists, F2 gone (fixed), F3 new
    d2 = m.record_findings("app.lab", [_finding("F1"), _finding("F3")], run_id="r2")
    assert d2.new == ["F3"]
    assert d2.fixed == ["F2"]
    assert d2.unchanged == ["F1"]
    # run 3: F2 returns → reopened
    d3 = m.record_findings("app.lab", [_finding("F2")], run_id="r3")
    assert d3.reopened == ["F2"]
    assert "F1" in d3.fixed and "F3" in d3.fixed
    assert "4 new" not in d3.summary()             # sanity on the summary text
    m.close()

def test_has_history_and_target_findings(tmp_path):
    m = _mem(tmp_path)
    assert not m.has_history("app.lab")
    m.record_findings("app.lab", [_finding("F1")], run_id="r1")
    assert m.has_history("app.lab")
    assert m.target_findings("app.lab", status="open")[0]["finding_id"] == "F1"
    assert "app.lab" in m.known_targets()
    m.close()


def test_knowledge_base_lookup_and_search():
    kb = KnowledgeBase()
    t = kb.lookup("sqli")
    assert t.cwe == "CWE-89" and t.detection and t.remediation
    assert kb.lookup("nonsense") is None
    hits = kb.search("injection")
    assert any(h.class_id == "sqli" for h in hits)
    web = kb.techniques_for("web")
    assert any(t.class_id == "xss_reflected" for t in web)
    assert "SQL injection" in kb.playbook("web")

