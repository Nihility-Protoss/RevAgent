# -*- coding: utf-8 -*-
"""entry_tools 公开工具边界、批量审查与 runtime 工具回归测试。"""

from tools.entry_store import shutdown_stores
from tools.entry_tools import (
    bb_create_entry,
    bb_get_entry,
    bb_review_entries,
    bb_query_entries,
    bb_get_entry_history,
    bb_set_runtime,
    bb_checkpoint,
    bb_load_checkpoint,
    bb_get_runtime,
)


def test_public_strings_and_batch_review(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    try:
        created = bb_create_entry(
            "function", "asm_address", "0x401000",
            {"conclusion": "候选", "confidence": "medium",
             "payload": {"func_name": "sub_401000", "candidate": {"priority": 9}},
             "evidence_refs": [], "annotations": {}, "relation_refs": []},
            {"phase": "phase1", "agent": "boundary", "run_id": "run-1"},
            "proj", "run-1:phase1:0x401000",
        )
        assert created["status"] == "success"
        public = created["data"]
        assert public["entry_type"] == "function"
        assert public["subject"]["kind"] == "asm_address"
        from tools.entry_store import get_store
        stored = get_store("proj").get_entry(public["entry_id"])
        assert type(stored.entry_type) is int

        reviewed = bb_review_entries(
            [{"entry_id": public["entry_id"], "version": 1}],
            "confirmed", "proj", reviewer="analyst", note="证据一致",
        )
        assert reviewed["status"] == "success"
        head = bb_get_entry(public["entry_id"], "proj")["data"]
        assert head["versions"][0]["review"]["status"] == "confirmed"
        assert head["head_version"] == 2

        conflict = bb_review_entries(
            [{"entry_id": public["entry_id"], "version": 1}], "rejected", "proj"
        )
        assert conflict["status"] == "error"
        assert conflict["reason"] == "version_conflict"
    finally:
        shutdown_stores()


def test_query_history_runtime_restart_and_clean_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    created = bb_create_entry(
        "function", "asm_address", "0x401000",
        {"conclusion": "候选", "confidence": "medium",
         "payload": {"func_name": "sub_401000"},
         "evidence_refs": [], "annotations": {}, "relation_refs": []},
        {"phase": "phase1", "agent": "boundary", "run_id": "run-1"},
        "proj", "op-1",
    )
    entry_id = created["data"]["entry_id"]
    assert bb_create_entry(
        "function", "asm_address", "0x401000",
        {"conclusion": "候选", "confidence": "medium",
         "payload": {"func_name": "sub_401000"},
         "evidence_refs": [], "annotations": {}, "relation_refs": []},
        {"phase": "phase1", "agent": "boundary", "run_id": "run-1"},
        "proj", "op-1",
    )["data"]["head_version"] == 1
    bb_review_entries([{"entry_id": entry_id, "version": 1}], "confirmed", "proj")
    bb_set_runtime("run_id", "run-1", "proj")
    bb_checkpoint("phase1_complete", "proj")
    shutdown_stores()

    assert bb_load_checkpoint("proj")["current_phase"] == "phase1_complete"
    assert bb_get_runtime("run_id", "proj") == "run-1"
    assert len(bb_get_entry_history(entry_id, "proj")["data"]["versions"]) == 2
    queried = bb_query_entries("proj", {
        "entry_type": "function", "subject.kind": "asm_address",
        "review.status": "confirmed",
    })
    assert queried["status"] == "success" and len(queried["data"]) == 1
    missing = bb_get_entry("missing", "proj")
    assert missing["status"] == "error"
    assert "Traceback" not in missing["error"]


def test_review_entries_rejects_duplicate_refs_without_writes(tmp_path, monkeypatch):
    """同一 entry_id 的重复 ref 必须整体拒绝且零写入（保持 all-or-nothing）。"""
    import inspect

    monkeypatch.chdir(tmp_path)
    try:
        created = bb_create_entry(
            "function", "asm_address", "0x401000",
            {"conclusion": "候选", "confidence": "medium",
             "payload": {"func_name": "sub_401000"},
             "evidence_refs": [], "annotations": {}, "relation_refs": []},
            {"phase": "phase1", "agent": "boundary", "run_id": "run-1"},
            "proj", "op-dup",
        )
        entry_id = created["data"]["entry_id"]

        result = bb_review_entries(
            [{"entry_id": entry_id, "version": 1},
             {"entry_id": entry_id, "version": 1}],
            "confirmed", "proj",
        )
        assert result["status"] == "error"
        assert result["reason"] == "invalid_request"
        # 零写入：head 版本号与版本数均未变化
        head = bb_get_entry(entry_id, "proj")["data"]
        assert head["head_version"] == 1
        assert len(bb_get_entry_history(entry_id, "proj")["data"]["versions"]) == 1

        # _wrap 不得擦除公开签名（functools.wraps 保留 __wrapped__/注解）
        signature = inspect.signature(bb_create_entry)
        params = list(signature.parameters)
        assert params == [
            "entry_type", "subject_kind", "subject_key", "output",
            "producer", "project_name", "idempotency_key",
        ]
    finally:
        shutdown_stores()
