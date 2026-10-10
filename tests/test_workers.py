"""workers.specs 测试：WorkerSpec 纯数据定义（LangGraph 迁移后）。

ADK LlmAgent 实例已移除；每个 worker 现在是一个 frozen WorkerSpec
（name/instruction/tools/output_key/output_schema），由 graph_nodes.make_worker_node
编译为 graph 节点。全部 6 个 spec 均已声明 output_schema（Pydantic 模型，
见 state.py）；本文件同时覆盖 schema 模型的样例校验与 parse_json_loose 容错回退。
"""
import asyncio
import dataclasses
import json

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import ValidationError

from graph_nodes import make_worker_node, parse_json_loose
from state import (
    ANALYSIS_TOPIC_VOCABULARY,
    AnalysisTask,
    ApiBehaviorAnalysis,
    BehaviorProfile,
    ExportInterfaceAnalysis,
    FunctionBoundaryAnalysis,
    SchedulerDecision,
    StringAnalysis,
    TaskManifest,
    VerificationReport,
)
from workers import specs
from workers.specs import (
    PHASE0_SPECS,
    PHASE1_SPECS,
    ALL_SPECS,
    WorkerSpec,
    api_behavior_profiler,
    behavior_profile_synthesizer,
    export_interface_analyzer,
    function_boundary_detector,
    load_arch_guide,
    scheduler,
    string_artifact_analyst,
    verification_agent,
)

ALL_WORKER_SPECS = [
    string_artifact_analyst,
    api_behavior_profiler,
    export_interface_analyzer,
    behavior_profile_synthesizer,
    function_boundary_detector,
]


def _tool_names(spec):
    return {(getattr(t, "__name__", None) or getattr(t, "name")) for t in spec.tools}


def test_all_seven_specs_exist():
    assert string_artifact_analyst is not None
    assert api_behavior_profiler is not None
    assert export_interface_analyzer is not None
    assert behavior_profile_synthesizer is not None
    assert function_boundary_detector is not None
    assert scheduler is not None
    assert verification_agent is not None


def test_spec_names_and_output_keys():
    expected = {
        "string_artifact_analyst": "string_analysis",
        "api_behavior_profiler": "api_behavior_analysis",
        "export_interface_analyzer": "export_interface_analysis",
        "behavior_profile_synthesizer": "behavior_profile",
        "function_boundary_detector": "function_boundary_analysis",
        "scheduler": "scheduler_decision",
        "verification_agent": "verification_report",
    }
    for spec in ALL_WORKER_SPECS + [scheduler, verification_agent]:
        assert spec.name in expected
        assert spec.output_key == expected[spec.name]


def test_specs_are_frozen_dataclasses():
    for spec in ALL_WORKER_SPECS + [scheduler, verification_agent]:
        assert dataclasses.is_dataclass(spec)
        assert spec.__dataclass_params__.frozen


def test_worker_specs_declare_minimal_toolset():
    expected_tools = {
        "string_artifact_analyst": {"bb_read_extract", "load_strings"},
        "api_behavior_profiler": {"bb_read_extract", "load_imports", "load_strings"},
        "export_interface_analyzer": {"bb_read_extract", "load_exports", "load_function_index"},
        "behavior_profile_synthesizer": {"bb_read_summary"},
        "function_boundary_detector": {
            "bb_read_extract", "load_function_index", "load_exports", "load_arch_guide",
        },
        "scheduler": {"bb_read_summary"},
        # 验证 Worker 只读黑板：summary 定位 high 发现，list/read artifact 回查原文
        "verification_agent": {"bb_read_summary", "bb_read_artifact", "bb_list_artifacts"},
    }
    for spec in ALL_WORKER_SPECS + [scheduler, verification_agent]:
        assert _tool_names(spec) == expected_tools[spec.name], spec.name


def test_load_arch_guide_tool_name():
    assert load_arch_guide.name == "load_arch_guide"


def test_all_specs_declare_output_schema():
    """全部 7 个 spec 均已 output_schema 化（P1 路线图项，2026-10-09 全覆盖；
    P2 验证 Worker 落地时同步补齐）。"""
    expected = [
        (string_artifact_analyst, StringAnalysis),
        (api_behavior_profiler, ApiBehaviorAnalysis),
        (export_interface_analyzer, ExportInterfaceAnalysis),
        (behavior_profile_synthesizer, BehaviorProfile),
        (function_boundary_detector, FunctionBoundaryAnalysis),
        (scheduler, SchedulerDecision),
        (verification_agent, VerificationReport),
    ]
    for spec, schema in expected:
        assert spec.output_schema is schema, spec.name


def test_spec_tuple_composition():
    assert PHASE0_SPECS == (
        string_artifact_analyst, api_behavior_profiler, export_interface_analyzer,
    )
    assert PHASE1_SPECS == (behavior_profile_synthesizer, function_boundary_detector)
    assert ALL_SPECS == PHASE0_SPECS + PHASE1_SPECS + (scheduler, verification_agent)


def test_all_workers_have_data_sufficiency_in_instruction():
    """所有 worker 的 instruction 都必须引用数据充足性检查。
    """
    for w in ALL_WORKER_SPECS:
        assert "insufficient_data" in w.instruction, f"{w.name} missing insufficient_data check"
        assert "status" in w.instruction, f"{w.name} missing status field requirement"


def test_phase3_prompt_has_insufficient_data_exit():
    """Phase 3 prompt 必须有显式的 insufficient_data 退出条件。
    """
    from workers.phase3.function_deep_analyzer import FUNC_ANALYSIS_PROMPT_TEMPLATE
    assert "insufficient_data" in FUNC_ANALYSIS_PROMPT_TEMPLATE
    assert "代码片段不足" in FUNC_ANALYSIS_PROMPT_TEMPLATE


def test_string_analyst_has_arch_detection():
    """Phase 0 字符串分析 worker 必须检测架构/语言/加壳器。
    """
    assert "arch_detection" in string_artifact_analyst.instruction
    assert "compiler_hints" in string_artifact_analyst.instruction
    assert "sample_form" in string_artifact_analyst.instruction
    assert "/rustc/" in string_artifact_analyst.instruction


def test_phase0_secondary_analysts_mention_arch_evidence():
    for w in (api_behavior_profiler, export_interface_analyzer):
        assert "编译语言" in w.instruction, f"{w.name} missing arch evidence hint"


def test_boundary_detector_uses_arch_guide():
    assert "load_arch_guide" in function_boundary_detector.instruction
    assert "__active__" in function_boundary_detector.instruction


def test_scheduler_instruction_is_preserved():
    assert "中央调度者" in scheduler.instruction
    assert "AWAITING_HUMAN_REVIEW" in scheduler.instruction


def test_workerspec_importable_from_specs_module():
    assert specs.WorkerSpec is WorkerSpec


# === 验证 Worker（P2 路线图项，2026-10-09 落地） ===================================

def test_verification_agent_instruction_is_five_section():
    """验证 Worker 提示词必须是五段式结构，且声明三分类与反幻觉约束。"""
    instruction = verification_agent.instruction
    for section in ["【角色定义】", "【输入数据】", "【分析维度】", "【输出格式】", "【误差控制】"]:
        assert section in instruction
    assert "insufficient_data" in instruction
    assert "verified" in instruction
    assert "disputed" in instruction
    assert "unverifiable" in instruction
    assert "bb_read_artifact" in instruction
    assert "bb_list_artifacts" in instruction
    assert "幻觉" in instruction


VERIFICATION_SAMPLE = {
    "status": "success",
    "verified": [
        {"finding": "存在 C2 URL http://evil.example/x", "source": "strings_summary",
         "verdict": "verified", "reason": "raw_value 逐字命中 artifact",
         "evidence_ref": "p0_string_artifact_analyst_20261009_010000: http://evil.example/x"},
    ],
    "disputed": [
        {"finding": "样本使用 HTTPS 回传", "source": "api_summary", "verdict": "disputed",
         "reason": "artifact 中无任何 TLS 相关 API 导入", "evidence_ref": ""},
    ],
    "unverifiable": [],
    "overall_assessment": "1 条发现被反驳，整体可信度中等",
}


def test_verification_report_validates_sample_payload():
    report = VerificationReport.model_validate(VERIFICATION_SAMPLE)
    assert report.status == "success"
    assert report.verified[0].verdict == "verified"
    assert report.disputed[0].reason
    # 全字段默认值兜底 + insufficient_data 最小输出
    assert VerificationReport.model_validate({}).status == "success"
    assert VerificationReport.model_validate(
        {"status": "insufficient_data", "reason": "无 high 置信度发现"}
    ).status == "insufficient_data"


def test_verification_report_buckets_flat_findings():
    """分类逻辑：模型输出扁平 findings 列表时，validator 必须按 verdict 归入三个桶。"""
    report = VerificationReport.model_validate({
        "status": "success",
        "findings": [
            {"finding": "a", "verdict": "verified", "reason": "r"},
            {"finding": "b", "verdict": "Disputed", "reason": "r"},      # 大小写容错
            {"finding": "c", "verdict": " unverifiable ", "reason": "r"},  # 空白容错
            {"finding": "d", "verdict": "maybe", "reason": "r"},         # 词表外 → unverifiable
            {"finding": "e"},                                            # 缺 verdict → unverifiable
            "非 dict 条目直接丢弃",
        ],
    })
    assert [f.finding for f in report.verified] == ["a"]
    assert [f.finding for f in report.disputed] == ["b"]
    assert [f.finding for f in report.unverifiable] == ["c", "d", "e"]
    assert all(f.verdict == "unverifiable" for f in report.unverifiable)


def test_verification_report_merges_buckets_with_flat_findings():
    """分桶与扁平 findings 并存时做合并，已有分桶不丢失。"""
    report = VerificationReport.model_validate({
        "verified": [{"finding": "kept", "verdict": "verified"}],
        "findings": [{"finding": "new", "verdict": "verified"}],
    })
    assert [f.finding for f in report.verified] == ["kept", "new"]


def test_verification_finding_verdict_normalized_not_rejected():
    """verdict 词表外的取值不报错，一律归一化为 unverifiable（宁缺毋滥）。"""
    report = VerificationReport.model_validate({
        "verified": [{"finding": "x", "verdict": "CERTAIN"}],
    })
    # 条目仍留在模型放置的桶里，但 verdict 值被归一化
    assert report.verified[0].verdict == "unverifiable"


def test_verification_worker_node_writes_artifact_and_summary(tmp_path, monkeypatch):
    """节点级冒烟：假模型返回分桶 JSON，state 写 verification_report 且黑板落盘。"""
    monkeypatch.chdir(tmp_path)
    fake = _PlainTextFakeChatModel(reply=json.dumps(VERIFICATION_SAMPLE, ensure_ascii=False))
    node = make_worker_node(verification_agent, llm=fake)
    result = asyncio.run(node({
        "sample_project_name": "verify_proj",
        "sample_export_dir": str(tmp_path),
    }))
    payload = result["verification_report"]
    assert payload["status"] == "success"
    assert len(payload["verified"]) == 1
    board = tmp_path / "data" / "output" / "verify_proj"
    assert list((board / "artifacts").glob("p3v_verification_agent_*.json"))
    assert (board / "summary" / "verification_summary.json").exists()


# === output_schema 模型校验（四个新增模型的合法样例） ===================================

# 样例字段与各自提示词"输出格式约束段"声明的 JSON 结构一一对应
API_BEHAVIOR_SAMPLE = {
    "status": "success",
    "total_imported_dlls": 5,
    "total_imported_functions": 42,
    "suspicious_apis": [
        {"api": "CreateRemoteThread", "dll": "kernel32.dll",
         "threat_category": "进程注入", "risk_description": "远程线程注入"},
    ],
    "behavior_profiles": [
        {"profile_name": "进程注入型",
         "matched_apis": ["OpenProcess", "VirtualAllocEx", "CreateRemoteThread"],
         "confidence": "high", "confidence_reason": "注入三件套齐备"},
    ],
    "mitre_techniques": [
        {"technique_id": "T1055", "technique_name": "Process Injection",
         "matched_apis": ["VirtualAllocEx", "CreateRemoteThread"]},
    ],
    "api_combination_risks": [
        {"apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"],
         "risk_description": "经典进程注入组合", "severity": "high"},
    ],
    "api_hash_resolution_indicators": {
        "suspicious": False, "evidence": "", "confidence": "low",
    },
    "ordinal_imports_analysis": {"count": 0, "suspicious": False, "notes": "无序数导入"},
    "overall_assessment": "导入表提示进程注入能力",
}

EXPORT_INTERFACE_SAMPLE = {
    "status": "success",
    "loading_pattern": {"pattern_type": "标准插件型", "confidence": "medium",
                        "evidence": ["仅 2 个 ordinal 导出"]},
    "ordinal_mapping": [
        {"ordinal": 1, "name": "DllInitialize", "address": "0x10001000",
         "likely_role": "初始化"},
    ],
    "tls_callback_analysis": {"has_tls_callback": False, "suspicious": False,
                              "assessment": "未发现 TLS 回调"},
    "packer_indicators": [
        {"indicator": "节名 UPX0/UPX1", "confidence": "high", "evidence": "UPX0"},
    ],
    "suspicious_exports": [
        {"name": "ServiceMain", "address": "0x10002000", "assessment": "服务入口导出"},
    ],
    "command_dispatcher_inference": {
        "has_command_dispatcher": True, "dispatcher_ordinal": 2,
        "cmd_offset_semantics": "+0x06=cmd_id", "confidence": "medium",
    },
    "callback_architecture": {"main_callback_addr": "0x10003000",
                              "string_callback_addr": None, "file_callback_addr": None,
                              "notes": "仅主回调可定位"},
    "overall_assessment": "标准 DLL 插件型导出表",
}

BEHAVIOR_PROFILE_SAMPLE = {
    "status": "success",
    "behavior_profile": {"primary_type": "Stealer", "secondary_types": ["Backdoor"],
                         "confidence": "high",
                         "evidence": ["sqlite3_open", "OpenClipboard"]},
    "command_and_residence": {"has_command_dispatcher": True,
                              "dispatcher_type": "switch-case",
                              "residence_type": "常驻", "notes": "cmd_id 固定偏移"},
    "info_stealing_capabilities": [
        {"target": "Chromium密码", "apis": ["sqlite3_open"], "confidence": "medium"},
    ],
    "persistence_mechanisms": [
        {"mechanism": "注册表Run键", "evidence": "RegSetValueEx Run", "confidence": "high"},
    ],
    "anti_debugging": [
        {"technique": "IsDebuggerPresent", "evidence": "IsDebuggerPresent 导入",
         "confidence": "medium"},
    ],
    "execution_chain_skeleton": "DllMain → 初始化 → 命令循环",
    "breakpoint_matrix": {
        "p0": [{"location": "VirtualAlloc 返回处", "purpose": "dump 解密缓冲",
                "address_hint": None}],
        "p1": [],
        "p2": [],
    },
    "analysis_checklist": {
        "export_table_strings": "covered", "execution_chain": "partial",
        "callback_decrypt": "not_covered", "command_semantics": "partial",
        "memory_execution": "not_covered", "info_stealing": "covered",
        "persistence": "covered", "anti_debug": "partial",
    },
    "overall_assessment": "Stealer 定型，证据充分",
    "recommended_next_steps": ["动态调试确认命令分发"],
}

SCHEDULER_SAMPLE = {
    "status": "success",
    "phase": "initial_complete",
    "action": "AWAITING_HUMAN_REVIEW",
    "summary": {"behavior_type": "Stealer", "confidence": "high",
                "high_risk_count": 3, "candidate_functions": 20},
    "details": {"string_key_findings": ["C2 URL"], "api_key_findings": ["注入组合"],
                "export_key_findings": ["ServiceMain"],
                "top_candidates": ["0x401000 sub_401000"]},
}


def test_new_output_schema_models_validate_sample_payloads():
    """四个新增模型都能校验各自提示词约定的合法样例数据。"""
    api = ApiBehaviorAnalysis.model_validate(API_BEHAVIOR_SAMPLE)
    assert api.suspicious_apis[0].api == "CreateRemoteThread"
    assert api.behavior_profiles[0].confidence == "high"
    assert api.api_hash_resolution_indicators.suspicious is False

    export = ExportInterfaceAnalysis.model_validate(EXPORT_INTERFACE_SAMPLE)
    assert export.loading_pattern.pattern_type == "标准插件型"
    assert export.command_dispatcher_inference.dispatcher_ordinal == 2
    assert export.callback_architecture.string_callback_addr is None

    behavior = BehaviorProfile.model_validate(BEHAVIOR_PROFILE_SAMPLE)
    assert behavior.behavior_profile.primary_type == "Stealer"
    assert behavior.breakpoint_matrix.p0[0].address_hint is None
    assert behavior.analysis_checklist.info_stealing == "covered"

    decision = SchedulerDecision.model_validate(SCHEDULER_SAMPLE)
    assert decision.action == "AWAITING_HUMAN_REVIEW"
    assert decision.summary.high_risk_count == 3
    assert decision.details.top_candidates == ["0x401000 sub_401000"]


@pytest.mark.parametrize("model", [
    ApiBehaviorAnalysis, ExportInterfaceAnalysis, BehaviorProfile, SchedulerDecision,
])
def test_new_output_schema_models_tolerate_minimal_payload(model):
    """insufficient_data 场景只输出 {status, reason} 时也必须能通过结构化解析。"""
    obj = model.model_validate({"status": "insufficient_data", "reason": "输入为空"})
    assert obj.status == "insufficient_data"
    assert model.model_validate({}).status == "success"  # 全字段有默认值


@pytest.mark.parametrize("model,payload", [
    (ApiBehaviorAnalysis, {**API_BEHAVIOR_SAMPLE, "behavior_profiles": [
        {"profile_name": "x", "matched_apis": [], "confidence": "certain"},
    ]}),
    (ExportInterfaceAnalysis, {**EXPORT_INTERFACE_SAMPLE, "loading_pattern": {
        "pattern_type": "标准插件型", "confidence": "certain",
    }}),
    (BehaviorProfile, {**BEHAVIOR_PROFILE_SAMPLE, "behavior_profile": {
        "primary_type": "Worm", "confidence": "low",
    }}),
    (SchedulerDecision, {**SCHEDULER_SAMPLE, "summary": {
        "behavior_type": "Stealer", "confidence": "certain",
        "high_risk_count": 1, "candidate_functions": 1,
    }}),
])
def test_new_output_schema_models_reject_invalid_enum(model, payload):
    """置信度/定型取值超出词表时校验必须失败（schema 不是摆设）。"""
    with pytest.raises(ValidationError):
        model.model_validate(payload)


# === parse_json_loose 容错回退（make_worker_node 结构化解析失败时的兜底路径） ================

def test_parse_json_loose_handles_fence_and_garbage():
    assert parse_json_loose('```json\n{"status": "success"}\n```') == {"status": "success"}
    assert parse_json_loose({"status": "success"}) == {"status": "success"}
    failed = parse_json_loose("这不是 JSON")
    assert failed["parse_error"] is True
    assert failed["status"] == "parse_failed"
    assert parse_json_loose(None)["parse_error"] is True


class _PlainTextFakeChatModel(BaseChatModel):
    """不声明结构化输出能力的假模型（AutoStrategy 退化为 ToolStrategy）。

    从不发起 tool_calls，因此 create_agent 无法产出 structured_response，
    用于验证 make_worker_node 的 parse_json_loose 回退路径。
    """

    reply: str = "{}"

    def _script(self, messages) -> str:
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "结构化摘要提取器" in text:
            return '{"status": "success", "key_findings": ["smoke"], "confidence": "low"}'
        return self.reply

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self._script(messages)))])

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self._script(messages)))])

    def bind_tools(self, tools, **kwargs):
        return self

    def bind(self, **kwargs):
        return self

    @property
    def _llm_type(self):
        return "plain-text-fake-chat-model"


def test_worker_node_falls_back_to_parse_json_loose(tmp_path, monkeypatch):
    """假模型不支持原生结构化输出时，节点回退 parse_json_loose 且 payload 不丢字段。"""
    monkeypatch.chdir(tmp_path)
    fake = _PlainTextFakeChatModel(reply=json.dumps(API_BEHAVIOR_SAMPLE, ensure_ascii=False))
    node = make_worker_node(api_behavior_profiler, llm=fake)
    result = asyncio.run(node({
        "sample_project_name": "fallback_proj",
        "sample_export_dir": str(tmp_path),
    }))
    payload = result["api_behavior_analysis"]
    assert payload["status"] == "success"
    assert payload["suspicious_apis"][0]["api"] == "CreateRemoteThread"
    # 回退路径同样完成 artifact 落盘
    artifacts = tmp_path / "data" / "output" / "fallback_proj" / "artifacts"
    assert list(artifacts.glob("p0_api_behavior_profiler_*.json"))


# === 提示词精修知识点断言（P1 路线图"技能知识精修"，2026-10-09 落地） ==================
# 只断言概念性关键词（非整句），避免措辞微调导致测试脆弱

def test_string_analyst_prompt_covers_loader_and_stealer_string_traits():
    """字符串分析提示词须含文件加载型标志字符串与浏览器凭据文件知识点。"""
    instruction = string_artifact_analyst.instruction
    assert "This program cannot be run in DOS mode" in instruction
    assert "Login Data" in instruction
    assert "logins.json" in instruction


def test_api_profiler_prompt_covers_hash_resolution_and_loader_chain():
    """API 画像提示词须含动态解析最小导入集与文件加载型五段链条知识点。"""
    instruction = api_behavior_profiler.instruction
    assert "LoadLibrary" in instruction
    assert "GetProcAddress" in instruction
    assert "VirtualProtect" in instruction
    assert "QueueUserAPC" in instruction


def test_export_analyzer_prompt_covers_plugin_entry_and_jump_table():
    """导出表分析提示词须含插件入口优先与跳转表命令分发知识点。"""
    instruction = export_interface_analyzer.instruction
    assert "插件入口" in instruction
    assert "跳转表" in instruction


def test_behavior_synthesizer_prompt_covers_type_form_cross_check():
    """行为定型提示词须含类型×形态交叉判别、反调试三件套与三关键地址知识点。"""
    instruction = behavior_profile_synthesizer.instruction
    assert "交叉判别" in instruction
    assert "CryptUnprotectData" in instruction
    assert "NtQueryInformationProcess" in instruction
    assert "读取点" in instruction


def test_boundary_detector_prompt_covers_form_specific_function_traits():
    """函数筛选提示词须含命令分发调度、插件入口与文件加载型三段知识点。"""
    instruction = function_boundary_detector.instruction
    assert "命令分发调度" in instruction
    assert "插件入口" in instruction
    assert "执行点" in instruction


# === A0 护栏提示词修正（导出优先 / 库函数反置顶 / 命令分发器置顶） ===========================

def test_boundary_detector_prompt_covers_guard_rules():
    """函数筛选提示词须与代码护栏同向：导出永远优先、库函数不得因高 xref 置顶。"""
    instruction = function_boundary_detector.instruction
    assert "导出函数永远优先" in instruction
    assert "运行时库函数" in instruction
    assert "命令分发器" in instruction
    assert "被导出函数调用" in instruction


# === A1 任务清单（task manifest）数据模型与 scheduler proposed_topics ======================

def test_analysis_task_model_defaults_and_vocab():
    """AnalysisTask 全字段有默认值；kind/status 词表越界必须校验失败。"""
    task = AnalysisTask()
    assert task.kind == "function"
    assert task.topic is None  # topic 可空
    assert task.status == "pending"
    assert task.function_addrs == [] and task.depends_on == []

    topic_task = AnalysisTask.model_validate({
        "task_id": "t1", "kind": "topic", "topic": "command_dispatcher",
        "depends_on": ["t0"], "output_doc": "docs/p/cmd.md",
    })
    assert topic_task.kind == "topic" and topic_task.topic == "command_dispatcher"

    with pytest.raises(ValidationError):
        AnalysisTask.model_validate({"kind": "wildcard"})
    with pytest.raises(ValidationError):
        AnalysisTask.model_validate({"status": "exploding"})


def test_task_manifest_model():
    """TaskManifest 嵌套 AnalysisTask 列表，空清单合法。"""
    manifest = TaskManifest.model_validate({
        "tasks": [
            {"task_id": "t1", "kind": "topic", "topic": "anti_analysis"},
            {"task_id": "t2", "kind": "function",
             "function_addrs": ["0x180013d80"], "depends_on": ["t1"]},
        ],
    })
    assert len(manifest.tasks) == 2
    assert manifest.tasks[1].function_addrs == ["0x180013d80"]
    assert TaskManifest().tasks == []
    # 主题词表常量完整（scheduler proposed_topics 的建议取值）
    assert "command_dispatcher" in ANALYSIS_TOPIC_VOCABULARY
    assert len(ANALYSIS_TOPIC_VOCABULARY) == 8


def test_scheduler_decision_proposed_topics():
    """SchedulerDecision 扩展 proposed_topics：缺省为空列表，样例校验通过。"""
    decision = SchedulerDecision.model_validate({
        **SCHEDULER_SAMPLE, "proposed_topics": ["command_dispatcher", "anti_analysis"],
    })
    assert decision.proposed_topics == ["command_dispatcher", "anti_analysis"]
    assert SchedulerDecision.model_validate(SCHEDULER_SAMPLE).proposed_topics == []


def test_scheduler_instruction_mentions_proposed_topics():
    """scheduler 提示词须要求按行为定型建议主题，并给出主题词表。"""
    instruction = scheduler.instruction
    assert "proposed_topics" in instruction
    assert "command_dispatcher" in instruction
    assert "anti_analysis" in instruction
