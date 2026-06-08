import asyncio
import os
import tempfile

import pytest
from google.adk.events.request_input import RequestInput
from google.adk.workflow._function_node import FunctionNode
from google.genai import types

from agent import (
    root_agent,
    analysis_orchestrator,
    run_analysis,
    AnalysisTokenReport,
    StageTokenStats,
    run_analysis_with_blackboard,
    setup_fn,
    setup_node,
    _parse_config_from_text,
)


class FakeCtx:
    def __init__(self, state=None):
        self.state = state or {}


async def _collect_async(gen):
    return [item async for item in gen]


def test_orchestrator_exists():
    """Verify the root agent is the dynamic workflow orchestrator."""
    assert isinstance(root_agent, FunctionNode)
    assert root_agent.name == "analysis_orchestrator"


def test_analysis_orchestrator_rerun_on_resume():
    """The orchestrator must rerun on resume so HITL works correctly."""
    assert analysis_orchestrator.rerun_on_resume is True


def test_analysis_orchestrator_is_async():
    """The orchestrator must be an async function."""
    import inspect
    assert inspect.iscoroutinefunction(analysis_orchestrator._func)


def test_root_agent_alias():
    """Verify root_agent points to the dynamic orchestrator."""
    assert root_agent is analysis_orchestrator


def test_run_analysis_signature():
    """Verify run_analysis function signature."""
    import inspect
    sig = inspect.signature(run_analysis)
    params = list(sig.parameters.keys())
    assert "sample_export_dir" in params
    assert "sample_project_name" in params
    assert "sample_type" in params


def test_token_report_basic():
    """Test AnalysisTokenReport collects usage correctly."""
    report = AnalysisTokenReport(sample_project_name="test")
    
    # Create a mock usage metadata object
    class MockUsage:
        promptTokenCount = 100
        candidatesTokenCount = 50
        totalTokenCount = 150
    
    # Create a mock event
    class MockEvent:
        usageMetadata = MockUsage()
        
        class MockNodeInfo:
            node_name = "test_node"
        nodeInfo = MockNodeInfo()
    
    report.add_event_usage(MockEvent())
    
    assert report.total_prompt_tokens == 100
    assert report.total_candidate_tokens == 50
    assert report.total_tokens == 150
    assert report.total_llm_calls == 1
    assert "test_node" in report.stages
    assert report.stages["test_node"].prompt_tokens == 100


def test_token_report_with_none_usage():
    """Test AnalysisTokenReport handles events without usage metadata."""
    report = AnalysisTokenReport(sample_project_name="test")
    
    class MockEventNoUsage:
        usageMetadata = None
    
    report.add_event_usage(MockEventNoUsage())
    
    assert report.total_tokens == 0
    assert report.total_llm_calls == 0


def test_token_report_str_output():
    """Test AnalysisTokenReport string representation."""
    report = AnalysisTokenReport(sample_project_name="test")
    
    class MockUsage:
        promptTokenCount = 1000
        candidatesTokenCount = 500
        totalTokenCount = 1500
    
    class MockEvent:
        usageMetadata = MockUsage()
        
        class MockNodeInfo:
            node_name = "scheduler"
        nodeInfo = MockNodeInfo()
    
    report.add_event_usage(MockEvent())
    output = str(report)
    
    assert "Token Usage Report: test" in output
    assert "Total LLM Calls: 1" in output
    assert "Total Tokens: 1,500" in output
    assert "scheduler" in output


def test_stage_token_stats_add_usage():
    """Test StageTokenStats accumulates usage."""
    stats = StageTokenStats(stage_name="test_stage")
    
    class MockUsage:
        promptTokenCount = 100
        candidatesTokenCount = 50
        totalTokenCount = 150
    
    stats.add_usage(MockUsage())
    assert stats.prompt_tokens == 100
    assert stats.candidate_tokens == 50
    assert stats.total_tokens == 150
    assert stats.call_count == 1
    
    stats.add_usage(MockUsage())
    assert stats.prompt_tokens == 200
    assert stats.call_count == 2


def test_run_analysis_with_blackboard_signature():
    """New runner should exist and be async."""
    import inspect
    assert inspect.iscoroutinefunction(run_analysis_with_blackboard)


def test_setup_fn_exists():
    assert isinstance(setup_fn, FunctionNode)
    assert setup_fn.name == "setup"
    assert setup_fn.rerun_on_resume is False


def test_setup_node_yields_request_input_on_first_run():
    """setup_node should yield a RequestInput with the setup message."""
    items = asyncio.run(_collect_async(setup_node(FakeCtx(), node_input=None)))
    assert len(items) == 1
    assert isinstance(items[0], RequestInput)
    assert "初始化配置" in items[0].message
    assert items[0].response_schema is str


def test_setup_node_passes_error_message():
    """setup_node should include the provided error message in the prompt."""
    items = asyncio.run(_collect_async(setup_node(FakeCtx(), node_input="bad input")))
    assert len(items) == 1
    assert isinstance(items[0], RequestInput)
    assert "[ERROR] 错误: bad input" in items[0].message


def test_parse_config_from_text_multiline(tmp_path):
    """Multiline EXPORT_DIR/PROJECT_NAME/WORK_DIR should parse correctly."""
    export_dir = tmp_path / "sample_export"
    export_dir.mkdir()

    user_text = (
        f"EXPORT_DIR={export_dir}\n"
        "PROJECT_NAME=sample_001\n"
        "WORK_DIR=D:\\analysis\\output"
    )

    config = _parse_config_from_text(user_text)
    assert config["export_dir"] == str(export_dir)
    assert config["project_name"] == "sample_001"
    assert config["work_dir"] == "D:\\analysis\\output"


def test_parse_config_from_text_pipe_separated(tmp_path):
    """Pipe-separated single-line format should parse correctly."""
    export_dir = tmp_path / "sample_export"
    export_dir.mkdir()

    user_text = f"EXPORT_DIR={export_dir}|PROJECT_NAME=sample_001|WORK_DIR=D:\\analysis\\output"

    config = _parse_config_from_text(user_text)
    assert config["export_dir"] == str(export_dir)
    assert config["project_name"] == "sample_001"
    assert config["work_dir"] == "D:\\analysis\\output"


def test_parse_config_from_text_missing_export_dir():
    """Missing EXPORT_DIR should raise ValueError."""
    with pytest.raises(ValueError, match="EXPORT_DIR is required"):
        _parse_config_from_text("PROJECT_NAME=sample_001")


def test_parse_config_from_text_missing_project_name(tmp_path):
    """Missing PROJECT_NAME should raise ValueError."""
    export_dir = tmp_path / "sample_export"
    export_dir.mkdir()

    with pytest.raises(ValueError, match="PROJECT_NAME is required"):
        _parse_config_from_text(f"EXPORT_DIR={export_dir}")


def test_parse_config_from_text_export_dir_not_exist(tmp_path):
    """Non-existent EXPORT_DIR should raise ValueError."""
    missing_dir = tmp_path / "does_not_exist"
    user_text = f"EXPORT_DIR={missing_dir}\nPROJECT_NAME=sample_001"

    with pytest.raises(ValueError, match="does not exist"):
        _parse_config_from_text(user_text)


def test_blackboard_directory_structure():
    """Running pre-extract should create .blackboard/ structure."""
    from tools.file_loaders import pre_extract_sample
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "data", "module.upx_export_for_ai")
    if not os.path.exists(fixture_dir):
        pytest.skip("Fixture data not found")

    orig_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        try:
            result = pre_extract_sample(fixture_dir, "test_project")
            assert result["status"] == "success"
            assert os.path.exists(os.path.join(".blackboard", "test_project", "extracts"))
            assert os.path.exists(os.path.join(".blackboard", "test_project", "extracts", "strings_extract.json"))
        finally:
            os.chdir(orig_cwd)
