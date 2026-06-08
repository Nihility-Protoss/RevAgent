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
    assert "string_artifact_analyst" in nodes
    assert "api_behavior_profiler" in nodes
    assert "export_interface_analyzer" in nodes
    assert "behavior_profile_synthesizer" in nodes
    assert "function_boundary_detector" in nodes
    assert "scheduler" in nodes


def test_workflow_edges():
    """Verify workflow edges form correct graph."""
    edges = [(e.from_node.name, e.to_node.name) for e in root_workflow.graph.edges]
    # Phase 0: START -> all 3 triage workers
    assert ("__START__", "string_artifact_analyst") in edges
    assert ("__START__", "api_behavior_profiler") in edges
    assert ("__START__", "export_interface_analyzer") in edges
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
