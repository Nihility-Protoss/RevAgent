"""Integration tests for the LangGraph orchestration layer (post ADK migration).

Pure-logic cases were ported from the old ADK orchestrator tests to
graph_nodes; orchestration is exercised end-to-end via build_graph(llm=fake)
with a scripted fake chat model — no real API tokens are consumed.
"""
import asyncio
import json
import os
import tempfile
from uuid import uuid4

import pytest
from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult, LLMResult

import graph_nodes
from graph import build_graph
from graph_nodes import (
    _load_active_guides_text,
    build_review_message,
    parse_approval_reply,
    resolve_active_guides,
)
from observability import TokenStatsCallback
from tools.blackboard_tools import board_base_dir
from tools.token_stats import AnalysisTokenReport, StageTokenStats


# === Scripted fake chat model ============================================

STRING_ANALYSIS_JSON = json.dumps({
    "status": "success",
    "suspicious_patterns": [{"pattern": "C2 URL", "risk_level": "high", "evidence": "http://evil.example/x"}],
    "overall_assessment": "疑似 Rust 编写的 Stealer",
    "arch_detection": {
        "language": "rust", "compiler_hints": ["rustc"], "packer_protector": ["upx"],
        "sample_form": "plain_exe", "confidence": "high", "evidence": ["/rustc/1.75.0/"],
    },
}, ensure_ascii=False)

API_ANALYSIS_JSON = json.dumps({
    "status": "success",
    "suspicious_apis": [{"api": "CreateRemoteThread", "dll": "kernel32", "threat_category": "进程注入", "risk_description": "注入"}],
    "overall_assessment": "进程注入特征",
}, ensure_ascii=False)

EXPORT_ANALYSIS_JSON = json.dumps({
    "status": "success",
    "loading_pattern": {"pattern_type": "标准插件型", "confidence": "medium"},
    "overall_assessment": "标准 DLL",
}, ensure_ascii=False)

BOUNDARY_JSON = json.dumps({
    "status": "success",
    "total_functions": 10,
    "filtered_functions": 8,
    "candidates": [{
        "func_addr": "0x401000", "func_name": "sub_401000", "size": 256, "xrefs": 12,
        "is_thunk": False, "is_export": False, "analysis_priority": 9,
        "priority_reason": "高交叉引用",
    }],
    "recommended_top_n": 1,
    "exclusion_notes": [],
    "export_functions_highlight": [],
}, ensure_ascii=False)

BEHAVIOR_JSON = json.dumps({
    "status": "success",
    "behavior_profile": {"primary_type": "Stealer", "secondary_types": [], "confidence": "high", "evidence": ["strings"]},
    "overall_assessment": "Stealer",
}, ensure_ascii=False)

SCHEDULER_JSON = json.dumps({
    "status": "success", "phase": "initial_complete", "action": "AWAITING_HUMAN_REVIEW",
    "summary": {"behavior_type": "Stealer", "confidence": "high", "high_risk_count": 1, "candidate_functions": 1},
    "details": {},
}, ensure_ascii=False)

FUNC_ANALYSIS_JSON = json.dumps({
    "func_addr": "0x401000", "func_name": "sub_401000", "status": "success",
    "functionality": "network_init", "key_apis": ["WSAStartup"],
    "suspicious_behaviors": ["C2 connect"], "related_functions": [],
    "confidence": "medium", "analysis_notes": "test",
}, ensure_ascii=False)

SHARD_JSON = json.dumps({
    "shard_id": 1, "status": "success",
    "suspicious_functions_summary": ["0x401000: C2"],
    "key_iocs": {"urls": [], "files": [], "registry": []},
    "behavior_pattern": "网络通信", "confidence": "medium",
    "uncertainties": ["样本量小"],
}, ensure_ascii=False)

FINAL_JSON = json.dumps({
    "status": "success", "malware_family": "Unknown", "confidence": "medium",
    "behavior_summary": "Stealer 行为",
    "key_iocs": {"urls": [], "files": [], "registry": []},
    "analyzed_functions": {"total": 1, "suspicious": 1, "key_functions": ["0x401000"]},
    "breakpoint_recommendations": {"P0": [], "P1": [], "P2": []},
    "uncertainties": ["假数据"], "recommendations": ["动态调试确认"],
}, ensure_ascii=False)

# Counts which script branch answered each model call; the smoke test
# asserts every expected branch fired and nothing fell through.
_CALL_COUNTS = {}


def _extractor_reply(prompt_text: str) -> str:
    marker = "输入 Artifact 类型:"
    artifact_type = "strings"
    if marker in prompt_text:
        artifact_type = prompt_text.split(marker, 1)[1].strip().splitlines()[0].strip()
    payload = {
        "worker": f"extractor_{artifact_type}",
        "key_findings": ["smoke"],
        "confidence": "high",
        "arch_detection": {"language": "rust", "confidence": "high"},
    }
    if artifact_type == "function_deep":
        payload["suspicious_behaviors"] = ["C2 connect"]
        payload["analysis_priority"] = 9
    return json.dumps(payload, ensure_ascii=False)


class ScriptedFakeChatModel(BaseChatModel):
    """Fake chat model dispatching canned JSON by prompt content.

    create_agent requires ``bind_tools`` support and a model profile
    advertising structured output (ProviderStrategy); both are faked here.
    """

    profile: dict = {"structured_output": True}

    def _script(self, messages: list[BaseMessage]) -> str:
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "结构化摘要提取器" in text:
            _CALL_COUNTS["extractor"] = _CALL_COUNTS.get("extractor", 0) + 1
            return _extractor_reply(text)
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
    """Minimal IDA export fixture: raw text files + one decompiled function."""
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


# === Token report (AnalysisTokenReport.add_usage) =======================

def test_token_report_basic():
    """Test AnalysisTokenReport collects usage correctly."""
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
    """Test AnalysisTokenReport string representation."""
    report = AnalysisTokenReport(sample_project_name="test")
    report.add_usage("scheduler", 1000, 500, 1500)
    output = str(report)

    assert "Token Usage Report: test" in output
    assert "Total LLM Calls: 1" in output
    assert "Total Tokens: 1,500" in output
    assert "scheduler" in output


def test_stage_token_stats_add_usage():
    """Test StageTokenStats accumulates usage."""
    stats = StageTokenStats(stage_name="test_stage")
    stats.add_usage(100, 50, 150)
    assert stats.prompt_tokens == 100
    assert stats.candidate_tokens == 50
    assert stats.total_tokens == 150
    assert stats.call_count == 1

    stats.add_usage(100, 50, 150)
    assert stats.prompt_tokens == 200
    assert stats.call_count == 2


# === TokenStatsCallback (LangGraph callback observability) ================

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
    """Models without usage_metadata on the message (e.g. OpenAI llm_output)."""
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


# === HITL approval protocol ==============================================

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


def test_approval_gate_node_confirm_via_prompt_human(monkeypatch):
    """approval_gate_node must read replies via graph_nodes.prompt_human."""
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: "CONFIRM")
    result = graph_nodes.approval_gate_node({"sample_project_name": "t"})
    assert result["phase2_human_decision"] == "CONFIRM"


def test_approval_gate_node_modify_via_prompt_human(monkeypatch):
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: "MODIFY 0x401000, 0x402000")
    result = graph_nodes.approval_gate_node({"sample_project_name": "t"})
    assert result["phase2_human_decision"] == "MODIFY 0x401000, 0x402000"
    assert result["human_approved_functions"] == ["0x401000", "0x402000"]


def test_approval_gate_node_defaults_to_confirm_after_invalid_replies(monkeypatch):
    replies = iter(["nope", "what?", "???"])
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: next(replies))
    result = graph_nodes.approval_gate_node({"sample_project_name": "t"})
    assert "CONFIRM" in result["phase2_human_decision"]


def test_build_review_message_includes_behavior_type():
    """Review message should include key fields from state."""
    state = {
        "behavior_profile": {"behavior_profile": {"primary_type": "Stealer", "confidence": "high"}},
        "string_analysis": {"suspicious_patterns": [{"risk_level": "high"}, {"risk_level": "high"}]},
        "api_behavior_analysis": {"suspicious_apis": [{"threat_category": "进程注入"}]},
        "function_boundary_analysis": {"candidates": [{"func_addr": "0x401000"}] * 15, "total_functions": 100},
    }
    msg = build_review_message(state)
    assert "Stealer" in msg
    assert "high" in msg
    assert "CONFIRM" in msg
    assert "MODIFY" in msg


# === Knowledge routing (resolve_active_guides) ===========================

def test_resolve_active_guides_rust(tmp_path, monkeypatch):
    """arch_detection=rust/high activates rust guide; meta file written."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(board_base_dir() + "/proj/summary")
    with open(board_base_dir() + "/proj/summary/strings_summary.json", "w", encoding="utf-8") as f:
        json.dump(
            {"arch_detection": {"language": "rust", "confidence": "high"}},
            f,
        )
    result = resolve_active_guides("proj")
    assert result["status"] == "success"
    with open(board_base_dir() + "/proj/meta/active_guides.json", encoding="utf-8") as f:
        meta = json.load(f)
    names = [g["name"] for g in meta["guides"]]
    assert names[0] == "windows_pe"
    assert "rust" in names


def test_resolve_active_guides_low_confidence_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs(board_base_dir() + "/proj/summary")
    with open(board_base_dir() + "/proj/summary/strings_summary.json", "w", encoding="utf-8") as f:
        json.dump(
            {"arch_detection": {"language": "unknown", "confidence": "low"}},
            f,
        )
    result = resolve_active_guides("proj")
    assert [g["name"] for g in result["guides"]] == ["windows_pe"]


def test_resolve_active_guides_missing_summary(tmp_path, monkeypatch):
    """Missing strings_summary must not break the pipeline; default + log."""
    monkeypatch.chdir(tmp_path)
    result = resolve_active_guides("proj")
    assert result["status"] == "success"
    assert [g["name"] for g in result["guides"]] == ["windows_pe"]
    assert os.path.exists(board_base_dir() + "/proj/meta/execution_log.jsonl")


def test_resolve_active_guides_prefers_state_param(tmp_path, monkeypatch):
    """arch_detection passed from state must activate rust without a summary file."""
    monkeypatch.chdir(tmp_path)
    result = resolve_active_guides(
        "proj", arch_detection={"language": "rust", "confidence": "high"}
    )
    names = [g["name"] for g in result["guides"]]
    assert names[0] == "windows_pe"
    assert "rust" in names
    # not relying on blackboard: no summary file exists
    assert not os.path.exists(board_base_dir() + "/proj/summary/strings_summary.json")


def test_load_active_guides_text_fallback_on_corrupt_meta(tmp_path, monkeypatch):
    """Corrupt meta/active_guides.json must fall back to the windows_pe baseline."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(board_base_dir() + "/proj/meta")
    with open(board_base_dir() + "/proj/meta/active_guides.json", "w", encoding="utf-8") as f:
        f.write("{invalid")
    text = _load_active_guides_text("proj")
    assert "PE" in text


# === Phase -1 pre-extraction =============================================

def test_blackboard_directory_structure():
    """Running pre-extract should create data/output structure."""
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


# === Graph assembly ======================================================

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
    """build_graph must register every phase node (fake model, no LLM calls)."""
    graph = build_graph(llm=ScriptedFakeChatModel())
    node_names = set(graph.get_graph().nodes.keys())
    assert EXPECTED_NODE_NAMES <= node_names


# === End-to-end orchestration smoke test =================================

def test_full_analysis_graph_smoke(tmp_path, monkeypatch):
    """Run the whole graph offline: pre_extract → Phase 0→4 with HITL CONFIRM.

    Asserts terminal-state keys, knowledge routing, blackboard artifacts and
    the final report; every scripted branch of the fake model must fire.
    """
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(graph_nodes, "prompt_human", lambda message: "CONFIRM")

    graph = build_graph(llm=ScriptedFakeChatModel())
    final_state = asyncio.run(graph.ainvoke({
        "sample_project_name": "test_proj",
        "sample_export_dir": export_dir,
        "sample_type": "auto",
    }))

    # Every worker + extractor + phase3/4 branch answered at least one call,
    # and no invocation fell through to the generic fallback.
    assert _CALL_COUNTS.get("unmatched", 0) == 0
    for branch in [
        "string_analyst", "api_profiler", "export_analyzer",
        "behavior_synthesizer", "boundary_detector", "scheduler",
        "extractor", "phase3", "shard", "aggregator",
    ]:
        assert _CALL_COUNTS.get(branch, 0) >= 1, f"fake model branch never fired: {branch}"

    # Terminal state carries the key outputs of every phase.
    assert final_state["sample_type"] == "pe"  # pre_extract 节点自动检测（imports+exports 齐全）
    assert final_state["scheduler_decision"]["action"] == "AWAITING_HUMAN_REVIEW"
    assert final_state["phase2_human_decision"] == "CONFIRM"
    assert final_state["final_report_ref"] == "bb://summary/p4_final_report"
    assert len(final_state["shard_reports"]) == 1
    assert len(final_state["func_analysis_refs"]) == 1
    assert final_state["func_analysis_refs"][0]["addr"] == "0x401000"

    # Phase 0 arch_detection routed the rust knowledge guide in.
    with open(board_base_dir() + "/test_proj/meta/active_guides.json", encoding="utf-8") as f:
        guide_names = [g["name"] for g in json.load(f)["guides"]]
    assert guide_names[0] == "windows_pe"
    assert "rust" in guide_names

    # Blackboard persistence: artifacts, per-phase summaries, final report.
    board = os.path.join(board_base_dir(), "test_proj")
    assert os.path.exists(os.path.join(board, "extracts", "strings_extract.json"))
    assert os.path.exists(os.path.join(board, "artifacts", "phase3_func_0x401000.json"))
    for summary_name in [
        "strings_summary", "api_summary", "exports_summary",
        "behavior_summary", "functions_summary", "p4_final_report",
    ]:
        assert os.path.exists(os.path.join(board, "summary", f"{summary_name}.json")), summary_name
    with open(os.path.join(board, "summary", "p4_final_report.json"), encoding="utf-8") as f:
        final_report = json.load(f)
    assert final_report["malware_family"] == "Unknown"


def test_full_analysis_graph_modify_branch(tmp_path, monkeypatch):
    """MODIFY reply must restrict Phase 3 to the human-approved addresses."""
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        graph_nodes, "prompt_human",
        lambda message: "MODIFY 0x401000,0x409999",
    )

    graph = build_graph(llm=ScriptedFakeChatModel())
    final_state = asyncio.run(graph.ainvoke({
        "sample_project_name": "test_proj",
        "sample_export_dir": export_dir,
        "sample_type": "auto",
    }))

    assert final_state["phase2_human_decision"] == "MODIFY 0x401000,0x409999"
    assert final_state["human_approved_functions"] == ["0x401000", "0x409999"]
    # Only 0x401000 exists in the boundary candidates and gets analyzed.
    assert final_state["func_analysis_refs"][0]["addr"] == "0x401000"
    assert "summary" in final_state["func_analysis_refs"][0]
    assert final_state["final_report_ref"] == "bb://summary/p4_final_report"


# === Context budget (128k) ================================================

def test_enforce_context_budget_passthrough():
    """Small prompts are returned untouched (normalized to messages)."""
    from graph_nodes import enforce_context_budget
    messages = [("system", "sys"), ("user", "hello")]
    result = enforce_context_budget(messages)
    assert len(result) == 2
    assert result[1].content == "hello"


def test_enforce_context_budget_truncates_oversized(monkeypatch, tmp_path):
    """A single oversized message gets truncated to fit the budget."""
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
    """Budget too small to hold anything must raise a clear error."""
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
