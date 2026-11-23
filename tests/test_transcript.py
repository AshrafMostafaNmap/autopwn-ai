"""Chat export: the transcript survives compaction and resume, and renders to
clean Markdown / HTML with every question and answer."""
from __future__ import annotations

from pathlib import Path

from conftest import ScriptedLLM, call, say

from autopwn.cli import main as cli_main
from autopwn.transcript import ExportMeta, build_turns, render_html, render_markdown


def _two_turns(make_session):
    llm = ScriptedLLM([call("recall_target", host="app.lab", content="checking memory first"),
                       say("## Result\n\n- nothing stored for **app.lab** yet"),
                       say("second answer")])
    s = make_session(llm, targets=["app.lab"])
    s.set_scope(authorized=True)
    s.chat("what do you know about app.lab?")
    s.chat("ok, and now?")
    return s


def test_every_question_answer_and_tool_is_recorded(make_session):
    s = _two_turns(make_session)
    turns = build_turns(s.chat_entries())
    assert [t.question for t in turns] == ["what do you know about app.lab?", "ok, and now?"]
    assert turns[0].answer.startswith("## Result") and turns[1].answer == "second answer"
    assert [(u.name, u.state) for u in turns[0].tools] == [("recall_target", "ok")]
    assert ("narration", "checking memory first") in turns[0].steps


def test_markdown_export_is_full_and_clean(make_session):
    s = _two_turns(make_session)
    md = s.export_chat("md").read_text()
    assert md.startswith("# what do you know about app.lab?")
    assert "## 1. You" in md and "## 2. You" in md
    assert "what do you know about app.lab?" in md and "second answer" in md
    assert "✓ `recall_target` host=app.lab" in md
    assert "app.lab (authorized)" in md

    clean = s.export_chat("md", tools=False).read_text()
    assert "recall_target" not in clean and "checking memory first" not in clean
    assert "second answer" in clean


def test_export_survives_compaction(make_session):
    s = _two_turns(make_session)
    assert s.compact()
    assert not any(m.content == "what do you know about app.lab?" for m in s.agent.conversation.messages)
    assert "what do you know about app.lab?" in s.export_chat("md").read_text()


def test_html_export_escapes_and_renders_markdown(make_session):
    llm = ScriptedLLM([say("**bold** and <script>alert(1)</script>")])
    s = make_session(llm)
    s.chat("<img src=x onerror=alert(1)> مرحبا")
    page = s.export_chat("html").read_text()
    assert page.startswith("<!doctype html>")
    assert "<strong>bold</strong>" in page
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;img src=x onerror=alert(1)&gt; مرحبا" in page
    assert 'dir="auto"' in page


def test_resumed_session_exports_both_halves(make_session):
    first = _two_turns(make_session)
    run_dir = first.ctx.run_dir
    first.close()
    again = make_session(ScriptedLLM([say("third answer")]), resume=str(run_dir))
    again.chat("one more")
    md = again.export_chat("md").read_text()
    for text in ("what do you know about app.lab?", "second answer", "one more", "third answer"):
        assert text in md


def test_interrupted_and_failed_turns_are_marked():
    entries = [{"kind": "user", "text": "q1", "ts": 1}, {"kind": "answer", "text": "", "error": "interrupted"},
               {"kind": "user", "text": "q2", "ts": 2}]
    md = render_markdown(build_turns(entries), ExportMeta())
    assert "**Error:** interrupted" in md and "the turn was interrupted" in md
    assert "AutoPwn AI session" in render_html(build_turns(entries), ExportMeta())


def test_legacy_session_falls_back_to_saved_conversation(make_session):
    s = _two_turns(make_session)
    s.transcript.path.unlink()
    md = s.export_chat("md").read_text()
    assert "what do you know about app.lab?" in md and "second answer" in md


def test_cli_export_latest_session(make_session, tmp_path, monkeypatch, capsys):
    s = _two_turns(make_session)
    s.save_state()
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[run]\nroot = "{tmp_path / "runs"}"\n')
    out = tmp_path / "chat.html"
    try:
        cli_main(["-c", str(cfg), "export", "--format", "html", "-o", str(out)])
    except SystemExit as e:
        assert e.code == 0
    assert "what do you know about app.lab?" in out.read_text()
    assert "chat exported" in capsys.readouterr().out
    assert Path(out).is_file()


def test_answer_headings_sit_below_the_turn_headings():
    entries = [{"kind": "user", "text": "q", "ts": 1},
               {"kind": "answer", "text": "# Top\n## Sub\n```\n# not a heading\n```\n#hashtag"}]
    md = render_markdown(build_turns(entries), ExportMeta())
    assert "#### Top" in md and "##### Sub" in md
    assert "\n# not a heading\n" in md and "\n#hashtag" in md


def test_text_export_is_plain_and_default(make_session):
    s = _two_turns(make_session)
    path = s.export_chat()
    assert path.suffix == ".txt"
    txt = path.read_text()
    assert "[1] YOU" in txt and "[2] AUTOPWN AI" in txt
    assert "what do you know about app.lab?" in txt and "second answer" in txt
    assert "Result" in txt and "• nothing stored for app.lab yet" in txt
    assert "**" not in txt and "## " not in txt
    assert "✓ recall_target" in txt
    assert "recall_target" not in s.export_chat("txt", tools=False).read_text()


def test_markdown_to_text_tables_code_links():
    from autopwn.transcript import markdown_to_text
    out = markdown_to_text("| a | b |\n|---|---|\n| 1 | **2** |\n\n```\nx = `y`\n```\n[docs](https://d.io) 2*3*4")
    assert "a  b" in out and "1  2" in out and "|" not in out
    assert "    x = `y`" in out
    assert "docs (https://d.io)" in out and "2*3*4" in out


def test_exports_in_the_same_second_do_not_overwrite(make_session):
    s = _two_turns(make_session)
    a, b = s.export_chat("txt"), s.export_chat("txt")
    assert a != b and a.is_file() and b.is_file()
