"""知识路由（resolve_active_guides）的纯单元测试。"""
from graph.gates import _load_active_guides_text, resolve_active_guides
from tools.entry_tools import (
    bb_create_entry,
    bb_get_runtime,
    bb_query_entries,
    bb_set_runtime,
)


# === 知识路由（resolve_active_guides） ===============================================

def _create_sample_entry(project_name="proj", arch_detection=None, run_id="run-1"):
    """通过条目黑板创建一个 sample 条目（模拟 Phase 0 字符串 Worker 的产物）。"""
    bb_create_entry(
        "sample", "sample", "sample",
        {"conclusion": "Rust 样本", "confidence": "high",
         "payload": {"overall_assessment": "Rust", "arch_detection": arch_detection or {}},
         "evidence_refs": [], "annotations": {}, "relation_refs": []},
        {"phase": "phase0", "agent": "strings", "run_id": run_id},
        project_name, f"{run_id}:phase0:strings:sample",
    )


def test_resolve_active_guides_reads_sample_entry(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bb_create_entry(
        "sample", "sample", "sample",
        {"conclusion": "Rust 样本", "confidence": "high",
         "payload": {"overall_assessment": "Rust", "arch_detection": {
             "language": "rust", "confidence": "high",
         }},
         "evidence_refs": [], "annotations": {}, "relation_refs": []},
        {"phase": "phase0", "agent": "strings", "run_id": "run-1"},
        "proj", "run-1:phase0:strings:sample",
    )
    result = resolve_active_guides("proj")
    assert "rust" in [guide["name"] for guide in result["guides"]]
    assert bb_get_runtime("active_guides", "proj")["guides"] == result["guides"]


def test_resolve_active_guides_rust(tmp_path, monkeypatch):
    """sample 条目携带 rust/high 的 arch_detection，会激活 rust 指南。"""
    monkeypatch.chdir(tmp_path)
    _create_sample_entry(arch_detection={
        "language": "rust", "confidence": "high",
    })
    result = resolve_active_guides("proj")
    assert result["status"] == "success"
    names = [g["name"] for g in result["guides"]]
    assert names[0] == "windows_pe"
    assert "rust" in names
    # 结果持久化到 runtime.active_guides
    runtime_doc = bb_get_runtime("active_guides", "proj")
    assert [g["name"] for g in runtime_doc["guides"]] == names


def test_resolve_active_guides_low_confidence_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _create_sample_entry(arch_detection={"language": "unknown", "confidence": "low"})
    result = resolve_active_guides("proj")
    assert [g["name"] for g in result["guides"]] == ["windows_pe"]


def test_resolve_active_guides_missing_sample_entry(tmp_path, monkeypatch):
    """没有任何 sample 条目时不能中断流水线；回退默认值并写 runtime 日志。"""
    monkeypatch.chdir(tmp_path)
    result = resolve_active_guides("proj")
    assert result["status"] == "success"
    assert [g["name"] for g in result["guides"]] == ["windows_pe"]
    log = bb_get_runtime("execution_log", "proj", []) or []
    assert any(e["event_type"] == "active_guides_default_fallback" for e in log)


def test_resolve_active_guides_prefers_state_param(tmp_path, monkeypatch):
    """显式传入的 arch_detection 优先于条目查询，且不需要任何条目。"""
    monkeypatch.chdir(tmp_path)
    result = resolve_active_guides(
        "proj", arch_detection={"language": "rust", "confidence": "high"}
    )
    names = [g["name"] for g in result["guides"]]
    assert names[0] == "windows_pe"
    assert "rust" in names
    # 不依赖条目黑板：此时不存在任何条目
    assert bb_query_entries("proj", {"entry_type": "sample"})["data"] == []


def test_load_active_guides_text_fallback_on_abnormal_runtime(tmp_path, monkeypatch):
    """runtime.active_guides 内容异常时必须回退到 windows_pe 基线。"""
    monkeypatch.chdir(tmp_path)
    bb_set_runtime("active_guides", {"guides": "not-a-list"}, "proj")
    text = _load_active_guides_text("proj")
    assert "PE" in text
