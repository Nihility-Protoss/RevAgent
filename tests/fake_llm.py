"""测试共享的脚本化假聊天模型与最小 IDA 导出 fixture。

从原 tests/test_integration.py 抽出，供 unit/graph 与 integration 下的测试复用，
不包含任何测试函数，因此不会被 pytest 收集。
"""
import json
import os

from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult


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
