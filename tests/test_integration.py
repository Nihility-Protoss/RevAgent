"""LangGraph 编排层的集成测试（ADK 迁移之后）。

纯逻辑用例已从旧的 ADK orchestrator 测试迁移到 graph_nodes；
编排通过 build_graph(llm=fake) 配合脚本化的假聊天模型端到端执行，
不消耗任何真实 API token。
"""
import asyncio
import json
import os
import tempfile
from types import SimpleNamespace
from uuid import uuid4

import pytest
from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult, LLMResult

import graph
import graph_nodes
import main
from graph import build_graph
from state import AnalysisState
from graph_nodes import (
    _load_active_guides_text,
    build_review_message,
    parse_approval_reply,
    resolve_active_guides,
)
from observability import TokenStatsCallback
from tools.blackboard_tools import board_base_dir
from tools.entry_tools import (
    bb_checkpoint,
    bb_create_entry,
    bb_get_entry,
    bb_get_runtime,
    bb_query_entries,
    bb_set_runtime,
    bb_write_worker_output,
)
from tools.token_stats import AnalysisTokenReport, StageTokenStats
from workers.specs import ALL_SPECS


# === 脚本化假聊天模型 =======================================================================

STRING_ANALYSIS_JSON = json.dumps({
    "status": "success",
    "conclusion": "疑似 Rust 编写的 Stealer，含 C2 URL",
    "confidence": "high",
    "payload": {
        "sample": {
            "overall_assessment": "疑似 Rust 编写的 Stealer",
            "arch_detection": {
                "language": "rust", "compiler_hints": ["rustc"], "packer_protector": ["upx"],
                "sample_form": "plain_exe", "confidence": "high", "evidence": ["/rustc/1.75.0/"],
            },
        },
        "findings": [{
            "category": "string", "name": "http://evil.example/x",
            "details": {"pattern": "C2 URL", "risk_level": "high", "evidence": "http://evil.example/x"},
        }],
    },
    "evidence_refs": ["strings_extract:0x402000"],
    "annotations": {},
}, ensure_ascii=False)

API_ANALYSIS_JSON = json.dumps({
    "status": "success",
    "conclusion": "进程注入特征",
    "confidence": "high",
    "payload": {
        "sample": None,
        "findings": [{
            "category": "api", "name": "CreateRemoteThread",
            "details": {"dll": "kernel32", "threat_category": "进程注入", "risk_description": "注入"},
        }],
    },
    "evidence_refs": ["imports_extract:CreateRemoteThread"],
    "annotations": {},
}, ensure_ascii=False)

EXPORT_ANALYSIS_JSON = json.dumps({
    "status": "success",
    "conclusion": "标准 DLL",
    "confidence": "medium",
    "payload": {
        "sample": None,
        "findings": [{
            "category": "export", "name": "DllMain",
            "details": {"loading_pattern": {"pattern_type": "标准插件型", "confidence": "medium"}},
        }],
    },
    "evidence_refs": ["exports_extract:DllMain"],
    "annotations": {},
}, ensure_ascii=False)

BOUNDARY_JSON = json.dumps({
    "status": "success",
    "conclusion": "筛出 1 个高优先级候选",
    "confidence": "high",
    "payload": {
        "candidates": [{
            "func_addr": "0x401000", "func_name": "sub_401000", "size": 256, "xrefs": 12,
            "is_thunk": False, "is_export": False, "analysis_priority": 9,
            "priority_reason": "高交叉引用",
        }],
    },
    "evidence_refs": ["functions_extract:0x401000"],
    "annotations": {},
}, ensure_ascii=False)

BEHAVIOR_JSON = json.dumps({
    "status": "success",
    "conclusion": "Stealer 行为定型",
    "confidence": "high",
    "payload": {
        "sample": None,
        "findings": [],
        "behavior_profile": {"primary_type": "Stealer", "secondary_types": [], "confidence": "high", "evidence": ["strings"]},
    },
    "evidence_refs": ["strings_summary"],
    "annotations": {},
}, ensure_ascii=False)

SCHEDULER_JSON = json.dumps({
    "status": "success",
    "conclusion": "初步分析完成，等待人工审查",
    "confidence": "high",
    "payload": {
        "action": "AWAITING_HUMAN_REVIEW",
        "selected_addresses": ["0x401000"],
        "summary": {"behavior_type": "Stealer", "confidence": "high", "high_risk_count": 1, "candidate_functions": 1},
    },
    "evidence_refs": [],
    "annotations": {},
}, ensure_ascii=False)

FUNC_ANALYSIS_JSON = json.dumps({
    "status": "success",
    "conclusion": "网络初始化",
    "confidence": "high",
    "payload": {
        "functionality": "初始化网络",
        "key_apis": ["WSAStartup"],
        "suspicious_behaviors": [{"behavior": "C2 connect", "evidence": "connect()"}],
        "related_functions": [],
        "analysis_notes": "test",
    },
    "evidence_refs": ["decompile:0x401000"],
    "annotations": {"recommended_name": "init_network"},
}, ensure_ascii=False)

SHARD_JSON = json.dumps({
    "status": "success", "conclusion": "局部行为模式: 网络通信",
    "confidence": "medium",
    "payload": {
        "details": {
            "suspicious_functions_summary": ["0x401000: C2"],
            "key_iocs": {"urls": [], "files": [], "registry": []},
            "uncertainties": ["样本量小"],
        },
    },
    "evidence_refs": ["decompile:0x401000"],
    "annotations": {},
}, ensure_ascii=False)

FINAL_JSON = json.dumps({
    "status": "success", "conclusion": "总体行为摘要: Stealer 行为",
    "confidence": "medium",
    "payload": {
        "details": {
            "malware_family": "Unknown",
            "behavior_summary": "Stealer 行为",
            "key_iocs": {"urls": [], "files": [], "registry": []},
            "analyzed_functions": {"total": 1, "suspicious": 1, "key_functions": ["0x401000"]},
            "breakpoint_recommendations": {"P0": [], "P1": [], "P2": []},
            "uncertainties": ["假数据"],
            "recommendations": ["动态调试确认"],
        },
    },
    "evidence_refs": [],
    "annotations": {},
}, ensure_ascii=False)

# 统计每个模型调用由哪个脚本分支应答；冒烟测试断言每个预期分支都被触发、没有落到兜底分支。
_CALL_COUNTS = {}


class ScriptedFakeChatModel(BaseChatModel):
    """按 prompt 内容分发预置 JSON 的假聊天模型。

    create_agent 需要 ``bind_tools`` 支持，以及声明了结构化输出
    （ProviderStrategy）的 model profile；这里把两者都做了伪造。
    """

    profile: dict = {"structured_output": True}

    def _script(self, messages: list[BaseMessage]) -> str:
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "中央调度者" in text:
            _CALL_COUNTS["scheduler"] = _CALL_COUNTS.get("scheduler", 0) + 1
            return SCHEDULER_JSON
        if "函数级分析专家" in text:
            _CALL_COUNTS["phase3"] = _CALL_COUNTS.get("phase3", 0) + 1
            return FUNC_ANALYSIS_JSON
        if "局部分析模式" in text:
            _CALL_COUNTS["shard"] = _CALL_COUNTS.get("shard", 0) + 1
            return SHARD_JSON
        if "汇总模式" in text:
            _CALL_COUNTS["aggregator"] = _CALL_COUNTS.get("aggregator", 0) + 1
            return FINAL_JSON
        if "恶意代码取证分析专家" in text:
            _CALL_COUNTS["string_analyst"] = _CALL_COUNTS.get("string_analyst", 0) + 1
            return STRING_ANALYSIS_JSON
        if "导入地址表" in text:
            _CALL_COUNTS["api_profiler"] = _CALL_COUNTS.get("api_profiler", 0) + 1
            return API_ANALYSIS_JSON
        if "导出表分析专家" in text:
            _CALL_COUNTS["export_analyzer"] = _CALL_COUNTS.get("export_analyzer", 0) + 1
            return EXPORT_ANALYSIS_JSON
        if "二进制分析专家" in text:
            _CALL_COUNTS["boundary_detector"] = _CALL_COUNTS.get("boundary_detector", 0) + 1
            return BOUNDARY_JSON
        if "行为定型" in text:
            _CALL_COUNTS["behavior_synthesizer"] = _CALL_COUNTS.get("behavior_synthesizer", 0) + 1
            return BEHAVIOR_JSON
        _CALL_COUNTS["unmatched"] = _CALL_COUNTS.get("unmatched", 0) + 1
        return '{"status": "success", "confidence": "low", "key_findings": []}'

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs,
    ) -> ChatResult:
        msg = AIMessage(content=self._script(messages))
        return ChatResult(generations=[ChatGeneration(message=msg)])

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs,
    ) -> ChatResult:
        msg = AIMessage(content=self._script(messages))
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def bind_tools(self, tools, **kwargs):
        return self

    def bind(self, **kwargs):
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted-fake-chat-model"


def _make_export_dir(base: str) -> str:
    """最小化的 IDA 导出 fixture：原始文本文件 + 一个反编译函数。"""
    export_dir = os.path.join(base, "export")
    os.makedirs(os.path.join(export_dir, "decompile"), exist_ok=True)
    with open(os.path.join(export_dir, "strings.txt"), "w", encoding="utf-8") as f:
        f.write("00401000 | 20 | ASCII | /rustc/1.75.0/library/core/src/panic.rs\n")
        f.write("00402000 | 24 | ASCII | http://evil.example/c2\n")
    with open(os.path.join(export_dir, "imports.txt"), "w", encoding="utf-8") as f:
        f.write("kernel32.dll\nCreateThread\n")
    with open(os.path.join(export_dir, "exports.txt"), "w", encoding="utf-8") as f:
        f.write("0x401000: DllMain\n")
    with open(os.path.join(export_dir, "function_index.txt"), "w", encoding="utf-8") as f:
        f.write("Function: sub_401000\nAddress: 0x401000\nCalls (12):\n")
    with open(os.path.join(export_dir, "decompile", "401000.c"), "w", encoding="utf-8") as f:
        f.write("int __fastcall sub_401000(int a1) { return a1 + 1; }\n")
    return export_dir


# === Token 报告（AnalysisTokenReport.add_usage） ======================================

def test_token_report_basic():
    """测试 AnalysisTokenReport 能正确收集用量。"""
    report = AnalysisTokenReport(sample_project_name="test")
    report.add_usage("test_node", 100, 50, 150)

    assert report.total_prompt_tokens == 100
    assert report.total_candidate_tokens == 50
    assert report.total_tokens == 150
    assert report.total_llm_calls == 1
    assert "test_node" in report.stages
    assert report.stages["test_node"].prompt_tokens == 100

    d = report.to_dict()
    assert d["sample_project_name"] == "test"
    assert d["total_llm_calls"] == 1
    assert d["stages"]["test_node"]["call_count"] == 1


def test_token_report_accumulates_multiple_stages():
    report = AnalysisTokenReport(sample_project_name="test")
    report.add_usage("scheduler", 100, 50, 150)
    report.add_usage("scheduler", 10, 5, 15)
    report.add_usage("aggregator", 1000, 500, 1500)

    assert report.total_llm_calls == 3
    assert report.total_tokens == 1665
    assert report.stages["scheduler"].call_count == 2
    assert report.stages["aggregator"].prompt_tokens == 1000


def test_token_report_str_output():
    """测试 AnalysisTokenReport 的字符串表示。"""
    report = AnalysisTokenReport(sample_project_name="test")
    report.add_usage("scheduler", 1000, 500, 1500)
    output = str(report)

    assert "Token Usage Report: test" in output
    assert "Total LLM Calls: 1" in output
    assert "Total Tokens: 1,500" in output
    assert "scheduler" in output


def test_stage_token_stats_add_usage():
    """测试 StageTokenStats 累加用量。"""
    stats = StageTokenStats(stage_name="test_stage")
    stats.add_usage(100, 50, 150)
    assert stats.prompt_tokens == 100
    assert stats.candidate_tokens == 50
    assert stats.total_tokens == 150
    assert stats.call_count == 1

    stats.add_usage(100, 50, 150)
    assert stats.prompt_tokens == 200
    assert stats.call_count == 2


# === TokenStatsCallback（LangGraph callback 可观测性） =====================================

def _llm_result_with_usage(input_tokens=100, output_tokens=50, total_tokens=150) -> LLMResult:
    msg = AIMessage(content="x", usage_metadata={
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    })
    return LLMResult(generations=[[ChatGeneration(message=msg)]])


def test_token_stats_callback_aggregates_usage_metadata():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start(
        {}, ["prompt"], run_id=run_id,
        metadata={"langgraph_node": "string_artifact_analyst"},
    )
    cb.on_llm_end(_llm_result_with_usage(100, 50, 150), run_id=run_id)

    assert cb.report.total_llm_calls == 1
    assert cb.report.total_prompt_tokens == 100
    assert cb.report.total_candidate_tokens == 50
    assert cb.report.total_tokens == 150
    stage = cb.report.stages["string_artifact_analyst"]
    assert stage.call_count == 1
    assert stage.prompt_tokens == 100


def test_token_stats_callback_on_chat_model_start():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_chat_model_start(
        {}, [[AIMessage(content="hi")]], run_id=run_id,
        metadata={"langgraph_node": "aggregator"},
    )
    cb.on_llm_end(_llm_result_with_usage(10, 5, 15), run_id=run_id)
    assert cb.report.stages["aggregator"].total_tokens == 15


def test_token_stats_callback_falls_back_to_llm_output_token_usage():
    """消息上没有 usage_metadata 的模型（例如 OpenAI 的 llm_output）。"""
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start({}, ["prompt"], run_id=run_id, metadata={"langgraph_node": "scheduler"})
    resp = LLMResult(
        generations=[[ChatGeneration(message=AIMessage(content="y"))]],
        llm_output={"token_usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}},
    )
    cb.on_llm_end(resp, run_id=run_id)

    assert cb.report.total_llm_calls == 1
    stage = cb.report.stages["scheduler"]
    assert stage.prompt_tokens == 8
    assert stage.candidate_tokens == 2
    assert stage.total_tokens == 10


def test_token_stats_callback_ignores_result_without_usage():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start({}, ["prompt"], run_id=run_id, metadata={"langgraph_node": "scheduler"})
    resp = LLMResult(generations=[[ChatGeneration(message=AIMessage(content="y"))]])
    cb.on_llm_end(resp, run_id=run_id)

    assert cb.report.total_llm_calls == 0
    assert cb.report.total_tokens == 0


def test_token_stats_callback_defaults_stage_to_unknown():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start({}, ["prompt"], run_id=run_id, metadata=None)
    cb.on_llm_end(_llm_result_with_usage(1, 1, 2), run_id=run_id)
    assert "unknown" in cb.report.stages


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
    """approval_gate_node 必须通过 graph_nodes.prompt_human 读取回复，CONFIRM 走审查写入。"""
    monkeypatch.chdir(tmp_path)
    _make_boundary_and_decision("proj", "run-1")
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: "CONFIRM")
    result = graph_nodes.approval_gate_node({"sample_project_name": "proj", "run_id": "run-1"})
    assert result == {}
    reviewed = bb_query_entries("proj", {"entry_type": "function"})["data"][0]
    assert reviewed["versions"][0]["review"]["status"] == "confirmed"


def test_approval_gate_node_defaults_to_confirm_after_invalid_replies(tmp_path, monkeypatch):
    """3 次无效回复后默认 CONFIRM，且与正常 CONFIRM 走相同的写入路径。"""
    monkeypatch.chdir(tmp_path)
    _make_boundary_and_decision("proj", "run-1")
    replies = iter(["nope", "what?", "???"])
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: next(replies))
    result = graph_nodes.approval_gate_node({"sample_project_name": "proj", "run_id": "run-1"})
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
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: "CONFIRM")

    result = graph_nodes.approval_gate_node({"sample_project_name": "proj", "run_id": "run-1"})
    assert result == {}
    reviewed = bb_get_entry(before["entry_id"], "proj")["data"]
    assert reviewed["versions"][0]["review"]["status"] == "confirmed"

    state = {
        "sample_project_name": "proj", "sample_export_dir": _make_export_dir(str(tmp_path)),
        "run_id": "run-1",
    }
    node = graph_nodes.make_phase3_node(llm=ScriptedFakeChatModel())
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
        graph_nodes, "prompt_human", lambda message: "MODIFY 0x401000,0x409999"
    )
    assert graph_nodes.approval_gate_node({
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


# === Phase -1 预提取（run_id 与 checkpoint 走 runtime 工具） ==========================

def test_pre_extract_resume_restores_run_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bb_set_runtime("run_id", "run-1", "proj")
    bb_checkpoint("pre_extract_complete", "proj")
    result = graph_nodes.pre_extract_node({
        "sample_project_name": "proj", "resume": True,
    })
    assert result["run_id"] == "run-1"
    assert not (tmp_path / "data" / "output" / "proj" / "meta").exists()


def test_pre_extract_fresh_generates_new_run_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        graph_nodes, "pre_extract_sample",
        lambda export_dir, project: {"status": "success"},
    )
    monkeypatch.setattr(
        graph_nodes, "detect_sample_type",
        lambda export_dir: {"sample_type": "pe", "confidence": "high", "indicators": []},
    )
    state = {"sample_project_name": "fresh", "sample_export_dir": "unused", "resume": False}
    first = graph_nodes.pre_extract_node(state)
    second = graph_nodes.pre_extract_node(state)
    assert first["run_id"] != second["run_id"]
    assert bb_get_runtime("run_id", "fresh") == second["run_id"]


def test_pre_extract_resume_missing_run_id_raises(tmp_path, monkeypatch):
    """resume 存在 checkpoint 但缺少 run_id 时必须明确报错。"""
    monkeypatch.chdir(tmp_path)
    bb_checkpoint("pre_extract_complete", "proj")
    bb_set_runtime("run_id", None, "proj")
    with pytest.raises(RuntimeError, match="resume 缺少 run_id"):
        graph_nodes.pre_extract_node({
            "sample_project_name": "proj", "resume": True,
        })


# === Phase -1 预提取 =======================================================================

def test_blackboard_directory_structure():
    """执行 pre-extract 应创建 data/output 目录结构。"""
    from tools.file_loaders import pre_extract_sample
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "data", "input", "module.upx_export_for_ai")
    if not os.path.exists(fixture_dir):
        pytest.skip("Fixture data not found")

    orig_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        try:
            result = pre_extract_sample(fixture_dir, "test_project")
            assert result["status"] == "success"
            assert os.path.exists(os.path.join(board_base_dir(), "test_project", "extracts"))
            assert os.path.exists(os.path.join(board_base_dir(), "test_project", "extracts", "strings_extract.json"))
        finally:
            os.chdir(orig_cwd)


# === 图组装 =======================================================================

EXPECTED_NODE_NAMES = {
    "pre_extract",
    "string_artifact_analyst", "api_behavior_profiler", "export_interface_analyzer",
    "resolve_guides",
    "behavior_profile_synthesizer", "function_boundary_detector",
    "scheduler", "approval_gate",
    "phase3_deep_analysis",
    "shard_synthesis", "aggregator",
}


def test_graph_structure():
    """build_graph 必须注册所有 phase 节点（使用假模型，不发起 LLM 调用）。"""
    graph = build_graph(llm=ScriptedFakeChatModel())
    node_names = set(graph.get_graph().nodes.keys())
    assert EXPECTED_NODE_NAMES <= node_names


def test_worker_nodes_return_empty_and_write_entries(tmp_path, monkeypatch):
    """六个 Worker 节点全部返回 {}，产物投影为版本化条目（无 extractor、无兜底分支）。"""
    monkeypatch.chdir(tmp_path)
    _CALL_COUNTS.clear()
    state = {
        "sample_project_name": "proj",
        "sample_export_dir": _make_export_dir(str(tmp_path)),
        "run_id": "run-1",
    }
    for spec in ALL_SPECS:
        node = graph_nodes.make_worker_node(spec, ScriptedFakeChatModel())
        assert asyncio.run(node(state)) == {}
    assert len(bb_query_entries("proj", {"entry_type": "sample"})["data"]) == 1
    assert len(bb_query_entries("proj", {"entry_type": "finding"})["data"]) >= 3
    assert len(bb_query_entries("proj", {"entry_type": "function"})["data"]) == 1
    assert len(bb_query_entries("proj", {"entry_type": "decision"})["data"]) == 1
    assert "extractor" not in _CALL_COUNTS
    assert "unmatched" not in _CALL_COUNTS


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
    shard_node = graph_nodes.make_shard_synthesis_node(llm=ScriptedFakeChatModel())
    assert asyncio.run(shard_node({"sample_project_name": "proj", "run_id": "run-1"})) == {}
    shards = bb_query_entries("proj", {
        "entry_type": "report", "payload.report_kind": "shard",
    })["data"]
    assert len(shards) == 1
    assert shards[0]["versions"][0]["relation_refs"][0]["version"] >= 1

    aggregate_node = graph_nodes.make_aggregator_node(llm=ScriptedFakeChatModel())
    result = asyncio.run(aggregate_node({"sample_project_name": "proj", "run_id": "run-1"}))
    final = bb_get_entry(result["final_report_entry_id"], "proj")["data"]
    assert final["entry_type"] == "report"
    assert final["versions"][0]["payload"]["report_kind"] == "final"
    assert final["versions"][0]["payload"]["details"]["malware_family"] == "Unknown"
    assert not (tmp_path / "data" / "output" / "proj" / "summary").exists()


# === 图状态白名单与运行退出落盘 ==========================================================


def test_analysis_state_contains_only_control_fields():
    assert set(AnalysisState.__annotations__) == {
        "sample_project_name", "sample_export_dir", "sample_type",
        "resume", "run_id", "final_report_entry_id",
    }


def test_run_analysis_calls_shutdown_on_error(monkeypatch):
    calls = []

    class FailingGraph:
        def get_graph(self):
            return SimpleNamespace(draw_mermaid_png=lambda output_file_path: None)

        async def ainvoke(self, state, config):
            raise RuntimeError("stop")

    monkeypatch.setattr(graph, "build_graph", lambda: FailingGraph())
    monkeypatch.setattr(main, "shutdown_stores", lambda: calls.append(True))
    with pytest.raises(RuntimeError, match="stop"):
        asyncio.run(main.run_analysis_with_blackboard(
            "proj", sample_export_dir="unused",
        ))
    assert calls == [True]


# === 端到端编排冒烟测试 =======================================================================

def test_full_analysis_graph_smoke(tmp_path, monkeypatch):
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: "CONFIRM")
    final_state = asyncio.run(build_graph(llm=ScriptedFakeChatModel()).ainvoke({
        "sample_project_name": "test_proj",
        "sample_export_dir": export_dir,
        "sample_type": "auto",
    }))
    assert set(final_state) <= {
        "sample_project_name", "sample_export_dir", "sample_type",
        "resume", "run_id", "final_report_entry_id",
    }
    for branch in (
        "string_analyst", "api_profiler", "export_analyzer",
        "behavior_synthesizer", "boundary_detector", "scheduler",
        "phase3", "shard", "aggregator",
    ):
        assert _CALL_COUNTS.get(branch, 0) >= 1, branch
    assert "extractor" not in _CALL_COUNTS
    assert "unmatched" not in _CALL_COUNTS
    report = bb_get_entry(final_state["final_report_entry_id"], "test_proj")["data"]
    assert report["versions"][0]["payload"]["details"]["malware_family"] == "Unknown"
    board = tmp_path / "data" / "output" / "test_proj"
    assert (board / "entries" / "store.pickle").exists()
    assert not (board / "artifacts").exists()
    assert not (board / "summary").exists()
    assert not (board / "meta").exists()


def test_full_analysis_graph_modify_branch(tmp_path, monkeypatch):
    """MODIFY 回复必须把 Phase 3 限制在人工批准的地址范围内（全部走条目黑板）。"""
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        graph_nodes, "prompt_human",
        lambda message: "MODIFY 0x401000,0x409999",
    )

    asyncio.run(build_graph(llm=ScriptedFakeChatModel()).ainvoke({
        "sample_project_name": "test_proj",
        "sample_export_dir": export_dir,
        "sample_type": "auto",
    }))

    decision = bb_query_entries("test_proj", {"entry_type": "decision"})["data"][0]
    selected = decision["versions"][0]["payload"]["selected_function_refs"]
    assert decision["versions"][0]["payload"]["summary"]["unknown_addresses"] == ["0x409999"]
    # 边界候选中只有 0x401000 存在，因此只有它会被深度分析。
    assert len(selected) == 1
    analyzed = bb_get_entry(selected[0]["entry_id"], "test_proj", include_history=True)["data"]
    assert analyzed["subject"]["key"] == "0x401000"
    assert analyzed["versions"][-1]["producer"]["phase"] == "phase3"
    funcs = bb_query_entries("test_proj", {"entry_type": "function"})["data"]
    assert len(funcs) == 1 and funcs[0]["subject"]["key"] == "0x401000"


# === 上下文预算（128k） =================================================================

def test_enforce_context_budget_passthrough():
    """小体积 prompt 原样返回（会先被规范化为 messages）。"""
    from graph_nodes import enforce_context_budget
    messages = [("system", "sys"), ("user", "hello")]
    result = enforce_context_budget(messages)
    assert len(result) == 2
    assert result[1].content == "hello"


def test_enforce_context_budget_truncates_oversized(monkeypatch, tmp_path):
    """单条超大消息会被截断以适配预算。"""
    from graph_nodes import enforce_context_budget
    # chdir 到无 config.yaml 的目录，让 MAX_CONTEXT_TOKENS 环境变量回退生效
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MAX_CONTEXT_TOKENS", "2000")
    big = "A" * 40000  # ~10k tokens，远超 2000 的预算
    result = enforce_context_budget([("user", big)])
    assert len(result) == 1
    assert "已截断" in result[0].content
    assert len(result[0].content) < len(big)
    # 头尾证据保留
    assert result[0].content.startswith("AAA")
    assert result[0].content.endswith("AAA")


def test_enforce_context_budget_raises_when_impossible(monkeypatch, tmp_path):
    """预算小到什么都装不下时必须抛出明确的错误。"""
    from graph_nodes import enforce_context_budget
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MAX_CONTEXT_TOKENS", "1")
    with pytest.raises(RuntimeError, match="上下文上限"):
        enforce_context_budget([("user", "x" * 4000)])


def test_max_context_tokens_default(monkeypatch, tmp_path):
    from graph_nodes import max_context_tokens
    monkeypatch.chdir(tmp_path)  # 避开仓库根目录的 config.yaml
    monkeypatch.delenv("MAX_CONTEXT_TOKENS", raising=False)
    assert max_context_tokens() == 128000
    monkeypatch.setenv("MAX_CONTEXT_TOKENS", "64000")
    assert max_context_tokens() == 64000
