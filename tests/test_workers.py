"""Tests for workers.specs: WorkerSpec pure-data definitions (post LangGraph migration).

The ADK LlmAgent instances are gone; each worker is now a frozen WorkerSpec
(name/instruction/tools/output_key/output_schema) compiled into a graph node by
graph_nodes.make_worker_node.
"""
import dataclasses

from state import FunctionBoundaryAnalysis, StringAnalysis
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


def test_all_six_specs_exist():
    assert string_artifact_analyst is not None
    assert api_behavior_profiler is not None
    assert export_interface_analyzer is not None
    assert behavior_profile_synthesizer is not None
    assert function_boundary_detector is not None
    assert scheduler is not None


def test_spec_names_and_output_keys():
    expected = {
        "string_artifact_analyst": "string_analysis",
        "api_behavior_profiler": "api_behavior_analysis",
        "export_interface_analyzer": "export_interface_analysis",
        "behavior_profile_synthesizer": "behavior_profile",
        "function_boundary_detector": "function_boundary_analysis",
        "scheduler": "scheduler_decision",
    }
    for spec in ALL_WORKER_SPECS + [scheduler]:
        assert spec.name in expected
        assert spec.output_key == expected[spec.name]


def test_specs_are_frozen_dataclasses():
    for spec in ALL_WORKER_SPECS + [scheduler]:
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
    }
    for spec in ALL_WORKER_SPECS + [scheduler]:
        assert _tool_names(spec) == expected_tools[spec.name], spec.name


def test_load_arch_guide_tool_name():
    assert load_arch_guide.name == "load_arch_guide"


def test_output_schema_only_on_structured_workers():
    assert string_artifact_analyst.output_schema is StringAnalysis
    assert function_boundary_detector.output_schema is FunctionBoundaryAnalysis
    for spec in (api_behavior_profiler, export_interface_analyzer,
                 behavior_profile_synthesizer, scheduler):
        assert spec.output_schema is None


def test_spec_tuple_composition():
    assert PHASE0_SPECS == (
        string_artifact_analyst, api_behavior_profiler, export_interface_analyzer,
    )
    assert PHASE1_SPECS == (behavior_profile_synthesizer, function_boundary_detector)
    assert ALL_SPECS == PHASE0_SPECS + PHASE1_SPECS + (scheduler,)


def test_all_workers_have_data_sufficiency_in_instruction():
    """All workers must reference data sufficiency check in their instruction."""
    for w in ALL_WORKER_SPECS:
        assert "insufficient_data" in w.instruction, f"{w.name} missing insufficient_data check"
        assert "status" in w.instruction, f"{w.name} missing status field requirement"


def test_phase3_prompt_has_insufficient_data_exit():
    """Phase 3 prompt must have explicit insufficient_data exit condition."""
    from workers.phase3.function_deep_analyzer import FUNC_ANALYSIS_PROMPT_TEMPLATE
    assert "insufficient_data" in FUNC_ANALYSIS_PROMPT_TEMPLATE
    assert "代码片段不足" in FUNC_ANALYSIS_PROMPT_TEMPLATE


def test_string_analyst_has_arch_detection():
    """Phase 0 string analyst must detect architecture/language/packer."""
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
