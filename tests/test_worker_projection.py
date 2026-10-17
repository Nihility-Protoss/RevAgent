"""Worker 统一产物投影测试：bb_write_worker_output 的三种 payload 形状与幂等语义。"""
from tools.entry_tools import bb_query_entries, bb_write_worker_output


def test_boundary_projection_reuses_function_identity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    output = {
        "status": "success", "conclusion": "筛出 1 个候选", "confidence": "high",
        "payload": {"candidates": [{
            "func_addr": "0x401000", "func_name": "sub_401000",
            "analysis_priority": 9, "priority_reason": "高 xrefs",
        }]},
        "evidence_refs": ["functions_extract:0x401000"], "annotations": {},
    }
    first = bb_write_worker_output("function_boundary_detector", output, "proj", "run-1")
    second = bb_write_worker_output("function_boundary_detector", output, "proj", "run-1")
    assert first["status"] == second["status"] == "success"
    assert first["written"] == 1
    assert second["written"] == 0
    entries = bb_query_entries("proj", {"entry_type": "function"})["data"]
    assert len(entries) == 1
    assert entries[0]["subject"]["key"] == "0x401000"
    assert entries[0]["versions"][0]["payload"]["candidate"]["priority"] == 9


def test_string_projection_links_findings_to_sample(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    output = {
        "status": "success", "conclusion": "Rust 样本含 C2", "confidence": "high",
        "payload": {
            "sample": {"overall_assessment": "Rust", "arch_detection": {"language": "rust"}},
            "findings": [{"category": "string", "name": "http://evil.example/c2",
                          "details": {"risk_level": "high"}}],
        },
        "evidence_refs": ["strings_extract:0x402000"], "annotations": {},
    }
    assert bb_write_worker_output("string_artifact_analyst", output, "proj", "run-1")["written"] == 2
    sample = bb_query_entries("proj", {"entry_type": "sample"})["data"][0]
    finding = bb_query_entries("proj", {"entry_type": "finding"})["data"][0]
    assert finding["versions"][0]["relation_refs"] == [{
        "entry_id": sample["entry_id"], "version": 1,
    }]


def test_scheduler_projection_resolves_entry_refs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bb_write_worker_output("function_boundary_detector", {
        "status": "success", "conclusion": "一个候选", "confidence": "high",
        "payload": {"candidates": [{"func_addr": "0x401000", "func_name": "sub_401000",
                                    "analysis_priority": 9}]},
        "evidence_refs": [], "annotations": {},
    }, "proj", "run-1")
    result = bb_write_worker_output("scheduler", {
        "status": "success", "conclusion": "等待人工审查", "confidence": "high",
        "payload": {"action": "AWAITING_HUMAN_REVIEW",
                    "selected_addresses": ["0x401000"], "summary": {"candidate_count": 1}},
        "evidence_refs": [], "annotations": {},
    }, "proj", "run-1")
    assert result["written"] == 1
    decision = bb_query_entries("proj", {"entry_type": "decision"})["data"][0]
    function = bb_query_entries("proj", {"entry_type": "function"})["data"][0]
    assert decision["versions"][0]["payload"]["selected_function_refs"] == [{
        "entry_id": function["entry_id"], "version": 1,
    }]


def test_insufficient_data_does_not_create_empty_finding(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = bb_write_worker_output("api_behavior_profiler", {
        "status": "insufficient_data", "conclusion": "导入数据为空", "confidence": "low",
        "payload": {"sample": None, "findings": []},
        "evidence_refs": [], "annotations": {},
    }, "proj", "run-1")
    assert result["written"] == 0
    assert bb_query_entries("proj", {"entry_type": "finding"})["data"] == []
