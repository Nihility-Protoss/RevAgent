"""HITL 审批协议与 approval_gate 节点的集成测试（CONFIRM / MODIFY / 默认放行）。"""
import asyncio

import graph
import graph.gates
import graph.phase3
from graph.gates import build_review_message, parse_approval_reply
from tests.fake_llm import ScriptedFakeChatModel, _CALL_COUNTS, _make_export_dir
from tools.entry_tools import bb_get_entry, bb_query_entries, bb_write_worker_output


# === HITL 审批协议 =======================================================================

def test_parse_approval_reply_confirm():
    decision, addrs = parse_approval_reply("CONFIRM")
    assert decision == "confirm"
    assert addrs is None


def test_parse_approval_reply_modify():
    decision, addrs = parse_approval_reply("MODIFY 0x401000,0x402000")
    assert decision == "modify"
    assert addrs == ["0x401000", "0x402000"]


def test_parse_approval_reply_invalid():
    decision, addrs = parse_approval_reply("maybe")
    assert decision == "invalid"
    assert addrs is None


def test_approval_gate_node_confirm_via_prompt_human(tmp_path, monkeypatch):
    """approval_gate_node 必须通过 graph.gates.prompt_human 读取回复，CONFIRM 走审查写入。"""
    monkeypatch.chdir(tmp_path)
    _make_boundary_and_decision("proj", "run-1")
    monkeypatch.setattr(graph.gates, "prompt_human", lambda message: "CONFIRM")
    result = graph.gates.approval_gate_node({"sample_project_name": "proj", "run_id": "run-1"})
    assert result == {}
    reviewed = bb_query_entries("proj", {"entry_type": "function"})["data"][0]
    assert reviewed["versions"][0]["review"]["status"] == "confirmed"


def test_approval_gate_node_defaults_to_confirm_after_invalid_replies(tmp_path, monkeypatch):
    """3 次无效回复后默认 CONFIRM，且与正常 CONFIRM 走相同的写入路径。"""
    monkeypatch.chdir(tmp_path)
    _make_boundary_and_decision("proj", "run-1")
    replies = iter(["nope", "what?", "???"])
    monkeypatch.setattr(graph.gates, "prompt_human", lambda message: next(replies))
    result = graph.gates.approval_gate_node({"sample_project_name": "proj", "run_id": "run-1"})
    assert result == {}
    reviewed = bb_query_entries("proj", {"entry_type": "function"})["data"][0]
    assert reviewed["versions"][0]["review"]["status"] == "confirmed"


def _make_boundary_and_decision(project, run_id, addresses=("0x401000",)):
    """写入函数候选条目与调度决策（scheduler 会把地址解析为函数 ref）。"""
    bb_write_worker_output("function_boundary_detector", {
        "status": "success", "conclusion": "候选已筛选", "confidence": "high",
        "payload": {"candidates": [{
            "func_addr": address, "func_name": f"sub_{address[2:]}",
            "analysis_priority": 9,
        } for address in addresses]},
        "evidence_refs": [], "annotations": {},
    }, project, run_id)
    bb_write_worker_output("scheduler", {
        "status": "success", "conclusion": "等待审查", "confidence": "high",
        "payload": {"action": "AWAITING_HUMAN_REVIEW",
                    "selected_addresses": list(addresses), "summary": {}},
        "evidence_refs": [], "annotations": {},
    }, project, run_id)


def test_phase3_appends_to_candidate_without_state_payload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _make_boundary_and_decision("proj", "run-1")
    before = bb_query_entries("proj", {"entry_type": "function"})["data"][0]
    monkeypatch.setattr(graph.gates, "prompt_human", lambda message: "CONFIRM")

    result = graph.gates.approval_gate_node({"sample_project_name": "proj", "run_id": "run-1"})
    assert result == {}
    reviewed = bb_get_entry(before["entry_id"], "proj")["data"]
    assert reviewed["versions"][0]["review"]["status"] == "confirmed"

    state = {
        "sample_project_name": "proj", "sample_export_dir": _make_export_dir(str(tmp_path)),
        "run_id": "run-1",
    }
    node = graph.phase3.make_phase3_node(llm=ScriptedFakeChatModel())
    assert asyncio.run(node(state)) == {}
    after = bb_get_entry(before["entry_id"], "proj", include_history=True)["data"]
    assert after["entry_id"] == before["entry_id"]
    assert after["versions"][-1]["producer"]["phase"] == "phase3"
    assert after["versions"][-1]["review"]["status"] == "pending"
    assert after["versions"][-1]["annotations"]["recommended_name"] == "init_network"
    call_count = _CALL_COUNTS["phase3"]
    assert asyncio.run(node(state)) == {}
    assert _CALL_COUNTS["phase3"] == call_count


def test_modify_updates_decision_without_rejecting_unselected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _make_boundary_and_decision("proj", "run-1", ("0x401000", "0x402000"))
    monkeypatch.setattr(
        graph.gates, "prompt_human", lambda message: "MODIFY 0x401000,0x409999"
    )
    assert graph.gates.approval_gate_node({
        "sample_project_name": "proj", "run_id": "run-1",
    }) == {}
    decision = bb_query_entries("proj", {"entry_type": "decision"})["data"][0]
    selected = decision["versions"][0]["payload"]["selected_function_refs"]
    selected_function = bb_query_entries("proj", {"subject.key": "0x401000"})["data"][0]
    unselected_function = bb_query_entries("proj", {"subject.key": "0x402000"})["data"][0]
    assert selected == [{"entry_id": selected_function["entry_id"], "version": 2}]
    assert unselected_function["versions"][0]["review"]["status"] == "pending"
    assert decision["versions"][0]["payload"]["summary"]["unknown_addresses"] == ["0x409999"]


def test_build_review_message_includes_behavior_type(tmp_path, monkeypatch):
    """审查消息应基于黑板 human_review 上下文生成，并包含 CONFIRM/MODIFY 协议。"""
    monkeypatch.chdir(tmp_path)
    _make_boundary_and_decision("proj", "run-1")
    msg = build_review_message({"sample_project_name": "proj"})
    assert "候选函数" in msg
    assert "CONFIRM" in msg
    assert "MODIFY" in msg
