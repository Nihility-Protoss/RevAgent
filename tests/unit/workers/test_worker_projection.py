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


def test_worker_task_contains_idempotency_key_formula(tmp_path, monkeypatch):
    """任务文本必须包含幂等键公式、本次调用的具体值与角色适用的 subject_key 约定。"""
    from graph.workers import build_worker_task
    from workers.specs import (
        function_boundary_detector, scheduler, string_artifact_analyst,
    )

    monkeypatch.chdir(tmp_path)
    state = {"sample_project_name": "proj", "sample_export_dir": "data/input/x"}
    task = build_worker_task(string_artifact_analyst, state, "run-9")
    assert "{run_id}:{phase}:{worker_name}:{subject_key}" in task
    assert "run-9:phase0:string_artifact_analyst:" in task
    # 样本/发现 Worker 拿到 sample + finding 约定
    assert '"sample"' in task
    assert "{category}:{name}" in task

    task = build_worker_task(function_boundary_detector, state, "run-9")
    assert "run-9:phase1:function_boundary_detector:" in task
    assert "0x" in task and "小写十六进制" in task

    task = build_worker_task(scheduler, state, "run-9")
    assert "run-9:phase2:scheduler:" in task
    assert '"phase2"' in task


def test_invalid_inner_payload_returns_error_not_keyerror(tmp_path, monkeypatch):
    """回归：WorkerOutput 通过但内层 validate_payload 拒绝（extra=forbid）时，
    bb_write_worker_output 必须返回 status=error，而不是 KeyError 逃逸。"""
    monkeypatch.chdir(tmp_path)
    result = bb_write_worker_output("string_artifact_analyst", {
        "status": "success", "conclusion": "含未知字段", "confidence": "high",
        "payload": {"sample": {"overall_assessment": "a", "arch_detection": {},
                               "unexpected_extra": 1}, "findings": []},
        "evidence_refs": [], "annotations": {},
    }, "proj", "run-1")
    assert result["status"] == "error"
    assert bb_query_entries("proj", {"entry_type": "sample"})["data"] == []


def test_projection_failure_is_logged_and_swallowed(tmp_path, monkeypatch):
    """投影失败（scheduler 地址未解析）记录 worker_projection_failed 事件且不抛异常。"""
    from graph.workers import _project_worker_output
    from tools.entry_tools import bb_get_runtime
    from workers.specs import scheduler

    monkeypatch.chdir(tmp_path)
    payload = {
        "status": "success", "conclusion": "等待人工审查", "confidence": "high",
        "payload": {"action": "AWAITING_HUMAN_REVIEW",
                    "selected_addresses": ["0x999999"], "summary": {}},
        "evidence_refs": [], "annotations": {},
    }
    result = _project_worker_output(scheduler, payload, "proj", "run-1")
    assert result["status"] == "error"
    assert bb_query_entries("proj", {"entry_type": "decision"})["data"] == []
    log = bb_get_runtime("execution_log", "proj", []) or []
    failures = [e for e in log if e["event_type"] == "worker_projection_failed"]
    assert len(failures) == 1
    assert failures[0]["details"]["worker"] == "scheduler"
