"""LangGraph 编排层的集成测试（ADK 迁移之后）。

纯逻辑用例已从旧的 ADK orchestrator 测试迁移到 graph_nodes；
编排通过 build_graph(llm=fake) 配合脚本化的假聊天模型端到端执行，
不消耗任何真实 API token。
"""
import asyncio
import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult, LLMResult
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

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


# === 脚本化假聊天模型 =======================================================================

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
    "candidates": [
        {"func_addr": "0x401000", "func_name": "sub_401000", "size": 256, "xrefs": 12,
         "is_thunk": False, "is_export": False, "analysis_priority": 9,
         "priority_reason": "高交叉引用"},
        {"func_addr": "0x402000", "func_name": "sub_402000", "size": 512, "xrefs": 8,
         "is_thunk": False, "is_export": False, "analysis_priority": 9,
         "priority_reason": "高交叉引用"},
        {"func_addr": "0x403000", "func_name": "sub_403000", "size": 384, "xrefs": 5,
         "is_thunk": False, "is_export": False, "analysis_priority": 8,
         "priority_reason": "命令分发疑似"},
        {"func_addr": "0x404000", "func_name": "sub_404000", "size": 128, "xrefs": 3,
         "is_thunk": False, "is_export": False, "analysis_priority": 7,
         "priority_reason": "普通候选"},
    ],
    "recommended_top_n": 4,
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
    # A2 双轨制：显式提议 command_dispatcher 主题，使 CONFIRM 路径同时扇出
    # 主题任务（0x401000 导出 + 高 xrefs 前 2）与函数兜底任务（0x404000）
    "proposed_topics": ["command_dispatcher"],
}, ensure_ascii=False)

TOPIC_ANALYSIS_JSON = json.dumps({
    "status": "success", "topic": "command_dispatcher",
    "summary": "命令分发器：switch-case 逐条分发，已还原 1 条命令语义",
    "findings": [{"subject": "cmd 0x06", "conclusion": "截屏回传", "confidence": "medium"}],
    "evidence": [{"address": "0x401000", "snippet": "switch (cmd_id)", "source": "decompile"}],
    "confidence": "medium",
    "unresolved": ["cmd 0x09 语义需动态验证"],
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
    # 主题摘要消费（A2 遗留修复）：aggregator 提炼主题结论要点进 p4_final_report
    "topic_conclusions": ["command_dispatcher: switch-case 分发，已还原 1 条命令"],
    "uncertainties": ["假数据"], "recommendations": ["动态调试确认"],
}, ensure_ascii=False)

VERIFICATION_JSON = json.dumps({
    "status": "success",
    "verified": [{
        "finding": "存在 C2 URL http://evil.example/c2", "source": "strings_summary",
        "verdict": "verified", "reason": "raw_value 逐字命中原始 artifact",
        "evidence_ref": "p0_string_artifact_analyst: http://evil.example/c2",
    }],
    "disputed": [],
    "unverifiable": [{
        "finding": "样本使用 TLS 回传", "source": "api_summary", "verdict": "unverifiable",
        "reason": "来源 artifact 缺失，无法核对", "evidence_ref": "",
    }],
    "overall_assessment": "1 条已验证，1 条无法核对",
}, ensure_ascii=False)

# 9 章实战手册骨架（对齐金标准 ALL_IN_ONE 结构；benchmark 章节维度要求全部命中）
REPORT_MD = (
    "# 恶意样本综合参考手册：test_proj\n\n"
    "## 1. 样本概览\n\n- 行为类型：Stealer [Phase 1]\n\n本章置信度：medium\n\n"
    "## 2. 完整执行流程图\n\nDllMain(0x401000) -> sub_404000\n\n"
    "## 3. 操作能力矩阵（驻留 / 持久化 / 注入 / 窃取 / C2）\n\n"
    "- C2 通信：存在 C2 URL [验证 verified]\n\n"
    "## 4. 关键函数速查表\n\n| 地址 | 功能 |\n|---|---|\n| 0x401000 | 入口 |\n\n"
    "## 5. 动态分析断点指南\n\n- P0：0x401000 入口观察\n\n"
    "## 6. 内存中的关键全局变量\n\n未发现\n\n"
    "## 7. C2 与配置提取方法\n\n- 断点提取方案\n\n"
    "## 8. IoC 指标汇总\n\n- http://evil.example/c2 [Phase 0 strings]\n\n"
    "## 9. 调试注意事项（反调试对抗 / 特殊结构 / 日志清理）\n\n- 无\n"
)

# 统计每个模型调用由哪个脚本分支应答；冒烟测试断言每个预期分支都被触发、没有落到兜底分支。
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
    """按 prompt 内容分发预置 JSON 的假聊天模型。

    create_agent 需要 ``bind_tools`` 支持，以及声明了结构化输出
    （ProviderStrategy）的 model profile；这里把两者都做了伪造。
    """

    profile: dict = {"structured_output": True}

    def _script(self, messages: list[BaseMessage]) -> str:
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        # 新增节点分支放在最前：关键字均为各自提示词独有，避免与旧分支互相误命中
        if "主题分析专家" in text:
            _CALL_COUNTS["topic"] = _CALL_COUNTS.get("topic", 0) + 1
            return TOPIC_ANALYSIS_JSON
        if "验证审计专家" in text:
            _CALL_COUNTS["verification_agent"] = _CALL_COUNTS.get("verification_agent", 0) + 1
            return VERIFICATION_JSON
        if "综合参考手册" in text:
            _CALL_COUNTS["report_generator"] = _CALL_COUNTS.get("report_generator", 0) + 1
            return REPORT_MD
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
    # A2 双轨制 fixture：补充其余候选函数的反编译文件（主题归组/函数兜底都会加载）
    for addr in ("402000", "403000", "404000"):
        with open(os.path.join(export_dir, "decompile", f"{addr}.c"), "w", encoding="utf-8") as f:
            f.write(f"int __fastcall sub_{addr}(int a1) {{ return a1; }}\n")
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


def test_approval_gate_node_requires_checkpointer():
    """interrupt() 化的审批门必须在带 checkpointer 的图中运行，不能直接裸调。"""
    with pytest.raises(RuntimeError):
        graph_nodes.approval_gate_node({"sample_project_name": "t"})


def test_build_review_message_includes_behavior_type():
    """审查消息应包含 state 中的关键字段。"""
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


# === 知识路由（resolve_active_guides） ===============================================

def test_resolve_active_guides_rust(tmp_path, monkeypatch):
    """arch_detection=rust/high 会激活 rust 指南，并写入 meta 文件。"""
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
    """缺失 strings_summary 不能中断流水线；使用默认值并记录日志。"""
    monkeypatch.chdir(tmp_path)
    result = resolve_active_guides("proj")
    assert result["status"] == "success"
    assert [g["name"] for g in result["guides"]] == ["windows_pe"]
    assert os.path.exists(board_base_dir() + "/proj/meta/execution_log.jsonl")


def test_resolve_active_guides_prefers_state_param(tmp_path, monkeypatch):
    """从 state 传入的 arch_detection 必须能在没有 summary 文件的情况下激活 rust。"""
    monkeypatch.chdir(tmp_path)
    result = resolve_active_guides(
        "proj", arch_detection={"language": "rust", "confidence": "high"}
    )
    names = [g["name"] for g in result["guides"]]
    assert names[0] == "windows_pe"
    assert "rust" in names
    # 不依赖 blackboard（黑板）：此时不存在 summary 文件
    assert not os.path.exists(board_base_dir() + "/proj/summary/strings_summary.json")


def test_load_active_guides_text_fallback_on_corrupt_meta(tmp_path, monkeypatch):
    """损坏的 meta/active_guides.json 必须回退到 windows_pe 基线。"""
    monkeypatch.chdir(tmp_path)
    os.makedirs(board_base_dir() + "/proj/meta")
    with open(board_base_dir() + "/proj/meta/active_guides.json", "w", encoding="utf-8") as f:
        f.write("{invalid")
    text = _load_active_guides_text("proj")
    assert "PE" in text


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
    # A2 双轨制：主题轨（wave0/wave1 两个节点共用 make_topic_node 工厂）+ 函数轨 + 第二波中继
    "phase3_dispatch", "phase3_topic", "phase3_function", "phase3_wave2", "phase3_topic_dep",
    # Phase 3 后置质量编排（docs 归档 + 质量/缺口/矛盾检查，纯代码节点）
    "orchestrator",
    "verification_agent",
    "shard_synthesis", "aggregator",
    "report_generator",
}


def test_graph_structure():
    """build_graph 必须注册所有 phase 节点（使用假模型，不发起 LLM 调用）。"""
    graph = build_graph(llm=ScriptedFakeChatModel())
    node_names = set(graph.get_graph().nodes.keys())
    assert EXPECTED_NODE_NAMES <= node_names


# === 端到端编排冒烟测试 =======================================================================

async def _run_graph_with_human_replies(graph, initial_state, replies, thread_id="test_thread"):
    """以 interrupt/resume 方式驱动带审批门的图。

    每次图在 approval_gate 挂起时，从 replies 依次取回复并通过
    Command(resume=回复) 恢复执行；replies 用完后兜底 CONFIRM，避免测试挂死。
    返回 (final_state, interrupt_count)，后者记录审批门挂起的总次数。
    """
    config = {"configurable": {"thread_id": thread_id}}
    pending_replies = iter(replies)
    interrupt_count = 0
    final_state = await graph.ainvoke(initial_state, config=config)
    while True:
        snapshot = graph.get_state(config)
        interrupts = [it for task in snapshot.tasks for it in task.interrupts]
        if not interrupts:
            return final_state, interrupt_count
        interrupt_count += len(interrupts)
        for _ in interrupts:
            reply = next(pending_replies, "CONFIRM")
            final_state = await graph.ainvoke(Command(resume=reply), config=config)


def test_full_analysis_graph_smoke(tmp_path, monkeypatch):
    """离线运行整张图：pre_extract → Phase 0→4，HITL 经 interrupt 挂起后回复 CONFIRM。

    断言终态字段、知识路由、blackboard（黑板）artifact 与最终报告；
    假模型的每个脚本分支都必须被触发。
    """
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)

    graph = build_graph(llm=ScriptedFakeChatModel(), checkpointer=MemorySaver())
    final_state, interrupt_count = asyncio.run(_run_graph_with_human_replies(
        graph,
        {
            "sample_project_name": "test_proj",
            "sample_export_dir": export_dir,
            "sample_type": "auto",
        },
        replies=["CONFIRM"],
    ))

    assert interrupt_count == 1

    # 每个 worker + extractor + 验证 + phase3/4 + 报告分支都至少应答过一次调用，
    # 且没有调用落到通用兜底分支。
    assert _CALL_COUNTS.get("unmatched", 0) == 0
    for branch in [
        "string_analyst", "api_profiler", "export_analyzer",
        "behavior_synthesizer", "boundary_detector", "scheduler",
        "extractor", "phase3", "topic", "verification_agent",
        "shard", "aggregator", "report_generator",
    ]:
        assert _CALL_COUNTS.get(branch, 0) >= 1, f"fake model branch never fired: {branch}"

    # 终态携带每个阶段的关键输出。
    assert final_state["sample_type"] == "pe"  # pre_extract 节点自动检测（imports+exports 齐全）
    assert final_state["scheduler_decision"]["action"] == "AWAITING_HUMAN_REVIEW"
    assert final_state["phase2_human_decision"] == "CONFIRM"
    assert final_state["final_report_ref"] == "bb://summary/p4_final_report"
    assert len(final_state["shard_reports"]) == 1

    # A2 双轨制：proposed_topics=["command_dispatcher"] 归组 0x401000(导出)+0x402000/0x403000(高 xrefs)，
    # 0x404000 未被主题覆盖 → 函数兜底任务
    assert len(final_state["func_analysis_refs"]) == 1
    assert final_state["func_analysis_refs"][0]["addr"] == "0x404000"
    assert len(final_state["topic_analysis_refs"]) == 1
    assert final_state["topic_analysis_refs"][0]["topic"] == "command_dispatcher"

    # 任务清单落盘：主题任务 + 函数兜底任务
    with open(board_base_dir() + "/test_proj/meta/task_manifest.json", encoding="utf-8") as f:
        manifest = json.load(f)
    assert {t["task_id"] for t in manifest["tasks"]} == {
        "topic_command_dispatcher", "func_0x404000",
    }

    # Phase 3 后置质量编排（orchestrator）：docs 归档 + 质量/缺口/矛盾计数写入 state
    orch = final_state["orchestrator_report"]
    assert orch["status"] == "success"
    assert orch["counts"]["docs_written"] == 2  # topic_command_dispatcher + func_0x404000
    assert orch["counts"]["gaps"] == 0
    docs_dir = os.path.join(board_base_dir(), "docs", "test_proj")
    assert os.path.exists(os.path.join(docs_dir, "AGENT_01_command_dispatcher.md"))
    assert os.path.exists(os.path.join(docs_dir, "AGENT_02_func_0x404000.md"))
    with open(os.path.join(docs_dir, "AGENT_01_command_dispatcher.md"), encoding="utf-8") as f:
        assert "## 分析结论" in f.read()  # 五要素段落
    # USER.md 骨架已由主题节点/orchestrator 自动创建
    assert os.path.exists(os.path.join(docs_dir, "USER.md"))

    # 验证 Worker（Phase 3 后置）：high 置信度发现分桶写入 state。
    verification = final_state["verification_report"]
    assert verification["status"] == "success"
    assert len(verification["verified"]) == 1
    assert len(verification["unverifiable"]) == 1

    # 综合报告 Worker：Markdown 手册落盘 + JSON 元数据 artifact。
    report_md_path = final_state["report_md_path"]
    assert os.path.basename(report_md_path) == "final_report.md"
    with open(report_md_path, encoding="utf-8") as f:
        report_text = f.read()
    assert "综合参考手册" in report_text
    # 9 章结构对齐金标准 ALL_IN_ONE 骨架：benchmark 章节结构维度满分
    from tools.benchmark import compare
    chapter_check = compare("", report_text)
    assert chapter_check["chapters"]["recall"] == 1.0
    assert chapter_check["chapters"]["missing"] == []

    # Phase 0 的 arch_detection 把 rust 知识指南路由了进来。
    with open(board_base_dir() + "/test_proj/meta/active_guides.json", encoding="utf-8") as f:
        guide_names = [g["name"] for g in json.load(f)["guides"]]
    assert guide_names[0] == "windows_pe"
    assert "rust" in guide_names

    # blackboard（黑板）持久化：artifact、各阶段 summary、最终报告。
    board = os.path.join(board_base_dir(), "test_proj")
    assert os.path.exists(os.path.join(board, "extracts", "strings_extract.json"))
    assert os.path.exists(os.path.join(board, "artifacts", "phase3_func_0x404000.json"))
    # A2 主题轨产物：完整 artifact + extractor 摘要
    assert os.path.exists(os.path.join(board, "artifacts", "topic_command_dispatcher.json"))
    assert os.path.exists(os.path.join(board, "summary", "topics", "command_dispatcher.json"))
    assert list(
        Path(board, "artifacts").glob("p3v_verification_agent_*.json")
    ), "验证 Worker artifact 未落盘"
    assert os.path.exists(os.path.join(board, "artifacts", "p4_final_report_meta.json"))
    with open(os.path.join(board, "artifacts", "p4_final_report_meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["report_path"] == final_state["report_md_path"]
    assert meta["source_refs"]["shard_report_count"] == 1
    for summary_name in [
        "strings_summary", "api_summary", "exports_summary",
        "behavior_summary", "functions_summary", "p4_final_report", "verification_summary",
    ]:
        assert os.path.exists(os.path.join(board, "summary", f"{summary_name}.json")), summary_name
    with open(os.path.join(board, "summary", "p4_final_report.json"), encoding="utf-8") as f:
        final_report = json.load(f)
    assert final_report["malware_family"] == "Unknown"
    # A2 遗留修复：aggregator 提炼主题结论要点（topics/ 摘要已进入聚合输入）
    assert final_report["topic_conclusions"] == [
        "command_dispatcher: switch-case 分发，已还原 1 条命令"
    ]


def test_full_analysis_graph_modify_branch(tmp_path, monkeypatch):
    """MODIFY 回复把 Phase 3 限制在人工批准的地址范围内，且圈外地址无条件采纳。

    A1 缺陷修复：0x409999 不在 LLM candidates 里，原实现会被过滤丢弃；
    现合成 FuncCandidate 补入，两个地址都必须被分析。
    """
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)

    graph = build_graph(llm=ScriptedFakeChatModel(), checkpointer=MemorySaver())
    final_state, interrupt_count = asyncio.run(_run_graph_with_human_replies(
        graph,
        {
            "sample_project_name": "test_proj",
            "sample_export_dir": export_dir,
            "sample_type": "auto",
        },
        replies=["MODIFY 0x401000,0x409999"],
    ))

    assert interrupt_count == 1
    assert final_state["phase2_human_decision"] == "MODIFY 0x401000,0x409999"
    assert final_state["human_approved_functions"] == ["0x401000", "0x409999"]
    # MODIFY 路径只产函数任务（无主题任务）：两个地址各一条引用，
    # 其中 0x409999 是合成候选（无反编译 fixture 也照常走分析流程）
    refs = {r["addr"]: r for r in final_state["func_analysis_refs"]}
    assert set(refs) == {"0x401000", "0x409999"}
    assert all("summary" in r for r in refs.values())
    assert final_state["topic_analysis_refs"] == []
    assert final_state["final_report_ref"] == "bb://summary/p4_final_report"


def test_full_analysis_graph_invalid_replies_default_confirm(tmp_path, monkeypatch):
    """连续 3 次无法识别的回复后审批门默认 CONFIRM 放行，图继续跑完。"""
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)

    graph = build_graph(llm=ScriptedFakeChatModel(), checkpointer=MemorySaver())
    final_state, interrupt_count = asyncio.run(_run_graph_with_human_replies(
        graph,
        {
            "sample_project_name": "test_proj",
            "sample_export_dir": export_dir,
            "sample_type": "auto",
        },
        replies=["nope", "what?", "???"],
    ))

    # 3 次无效回复对应 3 次 interrupt 挂起，之后默认 CONFIRM，不再挂起
    assert interrupt_count == 3
    assert "CONFIRM" in final_state["phase2_human_decision"]
    assert "human_approved_functions" not in final_state
    assert final_state["final_report_ref"] == "bb://summary/p4_final_report"
    # 默认 CONFIRM 路径与冒烟测试一致：主题归组后 0x404000 走函数兜底
    assert final_state["func_analysis_refs"][0]["addr"] == "0x404000"


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
