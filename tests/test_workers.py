"""workers.specs 测试：WorkerSpec 纯数据定义（统一 WorkerOutput 契约）。

每个 worker 是一个 frozen WorkerSpec（name/instruction/output_schema），
由 graph_nodes.make_worker_node 编译为 graph 节点；工具集不再声明在 spec 上，
由 tools.agent_tools.get_agent_tools 按角色动态注入（本文件按 minimal 模式断言）。
"""
import dataclasses

from tools.agent_tools import MINIMAL_ROLE_TOOLS, get_agent_tools
from tools.entry_models import WorkerOutput
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
    scheduler,
    string_artifact_analyst,
)

ALL_WORKER_SPECS = [
    string_artifact_analyst,
    api_behavior_profiler,
    export_interface_analyzer,
    behavior_profile_synthesizer,
    function_boundary_detector,
]


def _minimal_tool_names(spec):
    tools = get_agent_tools(spec.name, "proj", "run-1", ".", mode="minimal")
    return {t.name for t in tools}


def test_all_six_specs_exist():
    assert string_artifact_analyst is not None
    assert api_behavior_profiler is not None
    assert export_interface_analyzer is not None
    assert behavior_profile_synthesizer is not None
    assert function_boundary_detector is not None
    assert scheduler is not None


def test_spec_names():
    expected = {
        "string_artifact_analyst",
        "api_behavior_profiler",
        "export_interface_analyzer",
        "behavior_profile_synthesizer",
        "function_boundary_detector",
        "scheduler",
    }
    for spec in ALL_WORKER_SPECS + [scheduler]:
        assert spec.name in expected


def test_specs_are_frozen_dataclasses():
    for spec in ALL_WORKER_SPECS + [scheduler]:
        assert dataclasses.is_dataclass(spec)
        assert spec.__dataclass_params__.frozen


def test_specs_only_declare_name_instruction_output_schema():
    """WorkerSpec 只保留 name / instruction / output_schema 三个字段。"""
    for spec in ALL_WORKER_SPECS + [scheduler]:
        fields = {f.name for f in dataclasses.fields(spec)}
        assert fields == {"name", "instruction", "output_schema"}, spec.name


def test_all_specs_use_worker_output_schema():
    for spec in ALL_WORKER_SPECS + [scheduler]:
        assert spec.output_schema is WorkerOutput, spec.name


def test_worker_tools_come_from_get_agent_tools():
    """每个 worker 的 minimal 工具集由 get_agent_tools 按角色注入。"""
    for spec in ALL_WORKER_SPECS + [scheduler]:
        assert _minimal_tool_names(spec) == set(MINIMAL_ROLE_TOOLS[spec.name]), spec.name


def test_all_workers_have_data_sufficiency_in_instruction():
    """所有 worker 的 instruction 都必须引用数据充足性检查。
    """
    for w in ALL_WORKER_SPECS:
        assert "insufficient_data" in w.instruction, f"{w.name} missing insufficient_data check"
        assert "status" in w.instruction, f"{w.name} missing status field requirement"


def test_all_workers_emit_worker_output_shell():
    """所有 worker 的 instruction 都必须要求统一 WorkerOutput 外壳字段。"""
    for w in ALL_WORKER_SPECS + [scheduler]:
        for field in ("conclusion", "confidence", "payload", "evidence_refs", "annotations"):
            assert field in w.instruction, f"{w.name} missing shell field {field}"


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


def test_boundary_detector_uses_read_arch_guide():
    """函数筛选改用 read_arch_guide 命令（active 或显式指南名），不再传 __active__。"""
    assert "read_arch_guide" in function_boundary_detector.instruction
    assert "active" in function_boundary_detector.instruction
    assert "__active__" not in function_boundary_detector.instruction
    assert "load_arch_guide" not in function_boundary_detector.instruction
    assert "project_name" not in function_boundary_detector.instruction


def test_boundary_detector_keeps_candidate_field_names():
    instruction = function_boundary_detector.instruction
    for field in (
        "func_addr", "func_name", "size", "xrefs",
        "is_thunk", "is_export", "analysis_priority", "priority_reason",
    ):
        assert field in instruction, f"boundary detector missing {field}"


def test_scheduler_instruction_is_preserved():
    assert "中央调度者" in scheduler.instruction
    assert "AWAITING_HUMAN_REVIEW" in scheduler.instruction
    assert "read_scheduler_context" in scheduler.instruction
    assert "selected_addresses" in scheduler.instruction


def test_workerspec_importable_from_specs_module():
    assert specs.WorkerSpec is WorkerSpec


def test_spec_tuple_composition():
    assert PHASE0_SPECS == (
        string_artifact_analyst, api_behavior_profiler, export_interface_analyzer,
    )
    assert PHASE1_SPECS == (behavior_profile_synthesizer, function_boundary_detector)
    assert ALL_SPECS == PHASE0_SPECS + PHASE1_SPECS + (scheduler,)
