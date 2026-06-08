from agent import (
    root_workflow,
    phase0_triage_swarm,
    phase1_deep_swarm,
    scheduler_agent,
    run_analysis,
)


def test_workflow_structure():
    """Verify the workflow agent structure."""
    assert root_workflow.name == "malware_analysis_workflow"
    assert len(root_workflow.sub_agents) == 3
    assert root_workflow.sub_agents[0].name == "phase0_triage_swarm"
    assert root_workflow.sub_agents[1].name == "phase1_deep_swarm"
    assert root_workflow.sub_agents[2].name == "scheduler"


def test_phase0_swarm():
    """Verify Phase 0 swarm contains 3 workers."""
    assert len(phase0_triage_swarm.sub_agents) == 3
    names = [a.name for a in phase0_triage_swarm.sub_agents]
    assert "string_artifact_analyst" in names
    assert "api_behavior_profiler" in names
    assert "export_interface_analyzer" in names


def test_phase1_swarm():
    """Verify Phase 1 swarm contains 2 workers."""
    assert len(phase1_deep_swarm.sub_agents) == 2
    names = [a.name for a in phase1_deep_swarm.sub_agents]
    assert "behavior_profile_synthesizer" in names
    assert "function_boundary_detector" in names


def test_scheduler_has_callback():
    """Verify scheduler has human review callback."""
    assert scheduler_agent.after_agent_callback is not None


def test_run_analysis_signature():
    """Verify run_analysis function signature."""
    import inspect
    sig = inspect.signature(run_analysis)
    params = list(sig.parameters.keys())
    assert "sample_export_dir" in params
    assert "sample_project_name" in params
    assert "sample_type" in params


def test_root_agent_alias():
    """Verify root_agent is an alias for root_workflow."""
    from agent import root_agent
    assert root_agent is root_workflow
