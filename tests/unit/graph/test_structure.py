"""图组装与图状态白名单的纯单元测试。"""
from graph import build_graph
from graph.state import AnalysisState

from tests.fake_llm import ScriptedFakeChatModel

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


def test_analysis_state_contains_only_control_fields():
    assert set(AnalysisState.__annotations__) == {
        "sample_project_name", "sample_export_dir", "sample_type",
        "resume", "run_id", "final_report_entry_id",
    }
