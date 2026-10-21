# -*- coding: utf-8 -*-
"""bb_build_context 过滤、排序、预算与分页回归测试。"""

from tools.entry_tools import (
    bb_create_entry, bb_validate_entry, bb_review_entries, bb_build_context,
)


def _make_function(project, index):
    address = f"0x{0x401000 + index:x}"
    result = bb_create_entry(
        "function", "asm_address", address,
        {"conclusion": f"函数 {index}", "confidence": "medium",
         "payload": {"func_name": f"sub_{index}", "candidate": {"priority": 10 - index},
                     "analysis": {"functionality": "network_init"}},
         "evidence_refs": [], "annotations": {}, "relation_refs": []},
        {"phase": "phase3", "agent": "deep", "run_id": "run-1"},
        project, f"run-1:phase3:{address}",
    )
    return result["data"]


def _make_context_fixture(project):
    entries = [_make_function(project, index) for index in range(10)]
    producer = {"phase": "phase3", "agent": "validator", "run_id": "run-1"}
    bb_validate_entry(entries[0]["entry_id"], 1, project, producer, conclusion_status="valid")
    bb_review_entries([{"entry_id": entries[0]["entry_id"], "version": 2}], "confirmed", project)
    bb_validate_entry(entries[1]["entry_id"], 1, project, producer, conclusion_status="valid")
    bb_validate_entry(entries[2]["entry_id"], 1, project, producer, data_status="invalid")
    bb_review_entries([{"entry_id": entries[3]["entry_id"], "version": 1}], "rejected", project)
    bb_validate_entry(entries[4]["entry_id"], 1, project, producer, subject_status="insufficient_data")
    return entries


def test_phase4_context_filters_sorts_and_paginates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    entries = _make_context_fixture("proj")
    first = bb_build_context("phase4_shard", "proj", token_budget=6000)
    assert first["status"] == "success"
    assert len(first["entries"]) == 5
    assert first["entries"][0]["entry_id"] == entries[0]["entry_id"]
    assert first["entries"][1]["entry_id"] == entries[1]["entry_id"]
    excluded = {entries[index]["entry_id"] for index in (2, 3, 4)}
    assert excluded.isdisjoint({item["entry_id"] for item in first["entries"]})
    assert first["next_cursor"] is not None
    assert first["omitted_count"] == 2

    second = bb_build_context(
        "phase4_shard", "proj", token_budget=6000, cursor=first["next_cursor"]
    )
    assert len(second["entries"]) == 2
    assert second["next_cursor"] is None
    assert {item["entry_id"] for item in first["entries"]}.isdisjoint(
        {item["entry_id"] for item in second["entries"]}
    )
    too_small = bb_build_context("phase4_shard", "proj", token_budget=1)
    assert too_small["status"] == "error"
    assert too_small["reason"] == "context_entry_too_large"


def test_aggregate_context_is_scoped_to_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for run_id in ("run-1", "run-2"):
        bb_create_entry(
            "report", "report", f"shard:{run_id}",
            {"conclusion": "局部报告", "confidence": "medium",
             "payload": {"report_kind": "shard", "shard_id": 1, "details": {}},
             "evidence_refs": [], "annotations": {}, "relation_refs": []},
            {"phase": "phase4", "agent": "shard", "run_id": run_id},
            "proj", f"{run_id}:phase4:shard:1",
        )
    context = bb_build_context("phase4_aggregate", "proj", run_id="run-1")
    assert len(context["entries"]) == 1
    assert context["entries"][0]["subject"]["key"] == "shard:run-1"
