"""Phase 4 报告条目化的本地节点测试（无 State 分片，relation_refs 精确溯源）。"""
import asyncio

import graph.phase4
from tests.fake_llm import ScriptedFakeChatModel
from tools.entry_tools import bb_create_entry, bb_get_entry, bb_query_entries


# === Phase 4 报告条目化（无 State 分片，relation_refs 精确溯源） =======================

def _make_phase3_function(project, run_id):
    return bb_create_entry(
        "function", "asm_address", "0x401000",
        {"conclusion": "网络初始化", "confidence": "medium",
         "payload": {"func_name": "sub_401000", "candidate": {"priority": 9},
                     "analysis": {"functionality": "network_init",
                                  "suspicious_behaviors": [{"behavior": "C2 connect"}]}},
         "evidence_refs": ["decompile:0x401000"],
         "annotations": {"recommended_name": "init_network"}, "relation_refs": []},
        {"phase": "phase3", "agent": "function_deep_analyzer", "run_id": run_id},
        project, f"{run_id}:phase3:function_deep_analyzer:0x401000",
    )


def test_phase4_reports_are_entries_with_source_refs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _make_phase3_function("proj", "run-1")
    shard_node = graph.phase4.make_shard_synthesis_node(llm=ScriptedFakeChatModel())
    assert asyncio.run(shard_node({"sample_project_name": "proj", "run_id": "run-1"})) == {}
    shards = bb_query_entries("proj", {
        "entry_type": "report", "payload.report_kind": "shard",
    })["data"]
    assert len(shards) == 1
    assert shards[0]["versions"][0]["relation_refs"][0]["version"] >= 1

    aggregate_node = graph.phase4.make_aggregator_node(llm=ScriptedFakeChatModel())
    result = asyncio.run(aggregate_node({"sample_project_name": "proj", "run_id": "run-1"}))
    final = bb_get_entry(result["final_report_entry_id"], "proj")["data"]
    assert final["entry_type"] == "report"
    assert final["versions"][0]["payload"]["report_kind"] == "final"
    assert final["versions"][0]["payload"]["details"]["malware_family"] == "Unknown"
    assert not (tmp_path / "data" / "output" / "proj" / "summary").exists()
