"""workers.knowledge 包的测试。"""


def test_registry_contains_windows_pe():
    from workers.knowledge import KNOWLEDGE_REGISTRY
    assert "windows_pe" in KNOWLEDGE_REGISTRY
    meta = KNOWLEDGE_REGISTRY["windows_pe"]
    assert meta.priority == 10
    assert meta.max_tokens == 1200
    assert "baseline" in meta.applies_to


def test_load_knowledge_success():
    from workers.knowledge import load_knowledge
    result = load_knowledge("windows_pe", "any_project")
    assert result["status"] == "success"
    assert result["name"] == "windows_pe"
    assert "PE" in result["content"]
    assert result["token_estimate"] <= 1200
    assert result.get("truncated") in (None, False)


def test_load_knowledge_unknown_name():
    from workers.knowledge import load_knowledge
    result = load_knowledge("no_such_guide", "any_project")
    assert result["status"] == "error"
    assert "error" in result


def test_all_registered_files_respect_token_budget():
    from tools.blackboard_tools import _estimate_tokens
    from workers.knowledge import KNOWLEDGE_REGISTRY
    for name, meta in KNOWLEDGE_REGISTRY.items():
        text = meta.path.read_text(encoding="utf-8")
        assert _estimate_tokens(text) <= meta.max_tokens, (
            f"knowledge file {name} exceeds token budget"
        )


def test_registry_contains_language_guides():
    from workers.knowledge import KNOWLEDGE_REGISTRY
    for name in ("cpp", "rust"):
        assert name in KNOWLEDGE_REGISTRY
        assert KNOWLEDGE_REGISTRY[name].priority == 90


def test_registry_contains_go_and_triage_guides():
    from workers.knowledge import KNOWLEDGE_REGISTRY
    assert "golang" in KNOWLEDGE_REGISTRY
    assert KNOWLEDGE_REGISTRY["golang"].priority == 90
    assert "file_loader_triage" in KNOWLEDGE_REGISTRY
    assert KNOWLEDGE_REGISTRY["file_loader_triage"].priority == 80


def test_match_guides_language_routing():
    from workers.knowledge import match_guides
    guides = match_guides({"language": "rust", "confidence": "high"})
    assert guides[0] == "windows_pe"
    assert "rust" in guides
    assert "cpp" not in guides


def test_match_guides_low_confidence_falls_back_to_baseline():
    from workers.knowledge import match_guides
    assert match_guides({"language": "unknown", "confidence": "low"}) == ["windows_pe"]
    assert match_guides({}) == ["windows_pe"]


def test_match_guides_file_loader_form():
    from workers.knowledge import match_guides
    guides = match_guides(
        {"language": "c_cpp", "confidence": "medium", "sample_form": "exe_file_loader"}
    )
    assert "cpp" in guides
    assert "file_loader_triage" in guides
    # priority 升序：windows_pe(10) < file_loader_triage(80) < cpp(90)
    assert guides.index("file_loader_triage") < guides.index("cpp")


def test_load_active_falls_back_when_meta_missing():
    from workers.knowledge import load_knowledge
    result = load_knowledge("__active__", "nonexistent_project")
    assert result["status"] == "success"
    assert result["guides"] == ["windows_pe"]
    assert "PE" in result["content"]


def test_load_active_reads_meta(tmp_path, monkeypatch):
    import json
    import os
    from tools.blackboard_tools import board_base_dir
    from workers.knowledge import load_knowledge
    monkeypatch.chdir(tmp_path)
    os.makedirs(board_base_dir() + "/proj/meta")
    with open(board_base_dir() + "/proj/meta/active_guides.json", "w", encoding="utf-8") as f:
        json.dump(
            {"status": "success",
             "guides": [{"name": "windows_pe"}, {"name": "rust"}]},
            f,
        )
    result = load_knowledge("__active__", "proj")
    assert result["guides"] == ["windows_pe", "rust"]
    assert "Rust" in result["content"]


def test_match_guides_generic_applies_to(monkeypatch):
    """仅凭通用 applies_to 标签路由的指南会被动态匹配。"""
    from pathlib import Path

    from workers.knowledge import KNOWLEDGE_REGISTRY, KnowledgeMeta, match_guides

    fake = KnowledgeMeta(
        name="python_guide",
        title="Python 样本静态分析方法论",
        source="",
        applies_to=["language:python"],
        priority=70,
        max_tokens=1200,
        path=Path("python_guide.md"),
    )
    monkeypatch.setitem(KNOWLEDGE_REGISTRY, "python_guide", fake)

    assert "python_guide" in match_guides({"language": "python", "confidence": "high"})
    assert "python_guide" not in match_guides({"language": "rust", "confidence": "high"})
