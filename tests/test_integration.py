import pytest
from agent import (
    root_workflow,
    root_agent,
    run_analysis,
    AnalysisTokenReport,
    StageTokenStats,
)


def test_workflow_structure():
    """Verify the workflow agent structure."""
    assert root_workflow.name == "malware_analysis_workflow"
    assert root_workflow.graph is not None
    nodes = [n.name for n in root_workflow.graph.nodes]
    assert "__START__" in nodes
    assert "setup" in nodes
    assert "string_artifact_analyst" in nodes
    assert "api_behavior_profiler" in nodes
    assert "export_interface_analyzer" in nodes
    assert "behavior_profile_synthesizer" in nodes
    assert "function_boundary_detector" in nodes
    assert "scheduler" in nodes


def test_workflow_edges():
    """Verify workflow edges form correct graph."""
    assert len(root_workflow.edges) == 4  # includes setup_agent edge

    edges = [(e.from_node.name, e.to_node.name) for e in root_workflow.graph.edges]
    # Setup: START -> setup
    assert ("__START__", "setup") in edges
    # Phase 0: setup -> all 3 triage workers
    assert ("setup", "string_artifact_analyst") in edges
    assert ("setup", "api_behavior_profiler") in edges
    assert ("setup", "export_interface_analyzer") in edges
    # Phase 1: Each Phase 0 worker -> both Phase 1 workers (fan-in/fan-out)
    assert ("string_artifact_analyst", "behavior_profile_synthesizer") in edges
    assert ("string_artifact_analyst", "function_boundary_detector") in edges
    # Phase 2: Each Phase 1 worker -> scheduler
    assert ("behavior_profile_synthesizer", "scheduler") in edges
    assert ("function_boundary_detector", "scheduler") in edges


def test_root_agent_alias():
    """Verify root_agent is an alias for root_workflow."""
    assert root_agent is root_workflow


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


import tempfile
import os


def test_run_analysis_with_blackboard_signature():
    """New runner should exist and be async."""
    import inspect
    from agent import run_analysis_with_blackboard
    assert inspect.iscoroutinefunction(run_analysis_with_blackboard)


def test_setup_fn_exists():
    from agent import setup_fn
    from google.adk.workflow._function_node import FunctionNode
    assert isinstance(setup_fn, FunctionNode)
    assert setup_fn.name == "setup"
    assert setup_fn.rerun_on_resume is True


def test_setup_node_yields_request_input_on_first_run():
    """First run with empty state and no node_input should yield RequestInput."""
    import asyncio
    from agent import setup_node
    from google.adk.events.request_input import RequestInput

    class FakeCtx:
        def __init__(self):
            self.state = {}

    async def _run():
        gen = setup_node(FakeCtx(), node_input=None)
        items = []
        async for item in gen:
            items.append(item)
        return items

    items = asyncio.run(_run())
    assert len(items) == 1
    assert isinstance(items[0], RequestInput)
    assert "初始化配置" in items[0].message
    assert items[0].response_schema is str


def test_setup_node_short_circuits_when_already_configured():
    """If state already has config, setup_node should return None immediately."""
    import asyncio
    from agent import setup_node

    class FakeCtx:
        def __init__(self):
            self.state = {
                "sample_export_dir": "D:\\analysis\\sample_001_export",
                "sample_project_name": "sample_001",
            }

    async def _run():
        gen = setup_node(FakeCtx(), node_input=None)
        items = []
        async for item in gen:
            items.append(item)
        return items

    items = asyncio.run(_run())
    assert items == []


def test_setup_node_parses_valid_config_on_resume(tmp_path):
    """Resume with a valid user reply should write config to state and return None."""
    import asyncio
    from agent import setup_node
    from google.genai import types

    export_dir = tmp_path / "sample_export"
    export_dir.mkdir()

    user_text = (
        f"EXPORT_DIR={export_dir}\n"
        "PROJECT_NAME=sample_001\n"
        "WORK_DIR=D:\\analysis\\output"
    )

    node_input = types.Content(
        role="user",
        parts=[
            types.Part(
                function_response=types.FunctionResponse(
                    id="req-1",
                    name="adk_request_input",
                    response={"result": user_text},
                )
            )
        ],
    )

    class FakeCtx:
        def __init__(self):
            self.state = {}

    ctx = FakeCtx()

    async def _run_with_ctx():
        gen = setup_node(ctx, node_input=node_input)
        items = []
        async for item in gen:
            items.append(item)
        return items

    items = asyncio.run(_run_with_ctx())
    assert items == []
    assert ctx.state["sample_export_dir"] == str(export_dir)
    assert ctx.state["sample_project_name"] == "sample_001"
    assert ctx.state["output_base"] == "D:\\analysis\\output"


def test_setup_node_re_requests_on_parse_failure():
    """Invalid user reply should yield a new RequestInput with an error message."""
    import asyncio
    from agent import setup_node
    from google.adk.events.request_input import RequestInput
    from google.genai import types

    node_input = types.Content(
        role="user",
        parts=[
            types.Part(
                function_response=types.FunctionResponse(
                    id="req-1",
                    name="adk_request_input",
                    response={"result": "this is not a valid config"},
                )
            )
        ],
    )

    class FakeCtx:
        def __init__(self):
            self.state = {}

    ctx = FakeCtx()

    async def _run():
        gen = setup_node(ctx, node_input=node_input)
        items = []
        async for item in gen:
            items.append(item)
        return items

    items = asyncio.run(_run())
    assert len(items) == 1
    assert isinstance(items[0], RequestInput)
    assert "错误" in items[0].message
    # State should remain unmodified
    assert "sample_export_dir" not in ctx.state


def test_setup_node_re_requests_on_missing_export_dir(tmp_path):
    """Valid-looking config pointing to a non-existent directory should re-request."""
    import asyncio
    from agent import setup_node
    from google.adk.events.request_input import RequestInput
    from google.genai import types

    missing_dir = tmp_path / "does_not_exist"
    user_text = f"EXPORT_DIR={missing_dir}\nPROJECT_NAME=sample_001"

    node_input = types.Content(
        role="user",
        parts=[
            types.Part(
                function_response=types.FunctionResponse(
                    id="req-1",
                    name="adk_request_input",
                    response={"result": user_text},
                )
            )
        ],
    )

    class FakeCtx:
        def __init__(self):
            self.state = {}

    ctx = FakeCtx()

    async def _run():
        gen = setup_node(ctx, node_input=node_input)
        items = []
        async for item in gen:
            items.append(item)
        return items

    items = asyncio.run(_run())
    assert len(items) == 1
    assert isinstance(items[0], RequestInput)
    assert "does not exist" in items[0].message


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
