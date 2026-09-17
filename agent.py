import os
import sys

# Ensure project root is in Python path for ADK CLI imports
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from workers.orchestrator import root_agent

import json
from datetime import datetime, timezone

from dotenv import load_dotenv
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Load environment variables
load_dotenv()

from tools.blackboard_tools import (
    bb_checkpoint, bb_load_checkpoint, bb_log_event,
    bb_write_artifact, bb_write_summary,
)
from tools.file_loaders import pre_extract_sample
from tools.state_utils import coerce_state_dict
from tools.token_stats import AnalysisTokenReport
from workers.extractor import build_extraction_prompt, extractor_agent


# === Runtime Entry ===
async def run_analysis(
    sample_export_dir: str,
    sample_project_name: str,
    sample_type: str = "auto"
) -> tuple:
    """Run the complete malware sample analysis workflow.

    Args:
        sample_export_dir: Path to IDA no-MCP export directory.
        sample_project_name: Sample project name for tracking.
        sample_type: File type (pe/lnk/elf/auto).

    Returns:
        Tuple of (runner, session_service, events, token_report)
    """

    session_service = InMemorySessionService()

    session = await session_service.create_session(
        app_name="malware_analysis",
        user_id="analyst_001",
        session_id=f"analysis_{sample_project_name}",
        state={
            "sample_project_name": sample_project_name,
            "sample_export_dir": sample_export_dir,
            "sample_type": sample_type,
            "analysis_phase": "initial",
            "execution_status": "RUNNING",
        }
    )

    runner = Runner(
        agent=root_agent,
        app_name="malware_analysis",
        session_service=session_service
    )

    content = types.Content(
        role="user",
        parts=[types.Part(
            text=f"分析样本: {sample_project_name}, 导出目录: {sample_export_dir}"
        )]
    )

    # Collect events and token usage
    token_report = AnalysisTokenReport(sample_project_name=sample_project_name)
    events = []

    for event in runner.run(
        user_id="analyst_001",
        session_id=session.id,
        new_message=content
    ):
        events.append(event)

        # Extract token usage from event
        token_report.add_event_usage(event)

        if event.is_final_response():
            print(f"完成: {event.content.parts[0].text}")

    # Print token report
    print(str(token_report))

    return runner, session_service, events, token_report


# === Phase -1 to Phase 2 Orchestration with Blackboard ===


async def run_analysis_with_blackboard(
    sample_export_dir: str,
    sample_project_name: str,
    sample_type: str = "auto",
    resume: bool = False,
):
    """Run complete analysis with blackboard context management and checkpointing.

    Args:
        sample_export_dir: Path to IDA no-MCP export directory.
        sample_project_name: Sample project name for tracking.
        sample_type: File type (pe/lnk/elf/auto).
        resume: If True, resume from last checkpoint if available.

    Returns:
        Tuple of (runner, session_service, events, token_report)
    """
    token_report = AnalysisTokenReport(sample_project_name=sample_project_name)

    # Phase -1
    state = bb_load_checkpoint(sample_project_name)
    if not resume or state is None:
        bb_log_event("run_start", {"mode": "fresh"}, sample_project_name)
        pre_result = pre_extract_sample(sample_export_dir, sample_project_name)
        if pre_result["status"] != "success":
            raise RuntimeError(f"Pre-extraction failed: {pre_result.get('error')}")
        bb_checkpoint("pre_extract_complete", sample_project_name)
        state = {"current_phase": "pre_extract_complete"}
    else:
        bb_log_event("run_start", {"mode": "resume", "phase": state.get("current_phase")}, sample_project_name)

    # Setup ADK session for Workflow
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="malware_analysis",
        user_id="analyst_001",
        session_id=f"analysis_{sample_project_name}",
        state={
            "sample_project_name": sample_project_name,
            "sample_export_dir": sample_export_dir,
            "sample_type": sample_type,
            "analysis_phase": "initial",
            "execution_status": "RUNNING",
        }
    )
    runner = Runner(agent=root_agent, app_name="malware_analysis", session_service=session_service)

    # Phase 0/1/2: run the workflow. Each worker runs as its own ADK session inside
    # workers/orchestrator (Phase 0/1 fan-out via asyncio.gather, not Workflow edges);
    # worker outputs are then persisted to the blackboard below.
    if state.get("current_phase") in ("pre_extract_complete", "phase0", "phase1", "phase2"):
        # Worker agents are assembled in workers/orchestrator; import here to keep
        # this module's top-level imports free of worker assembly.
        from workers.phase0.string_artifact_analyst import string_artifact_analyst
        from workers.phase0.api_behavior_profiler import api_behavior_profiler
        from workers.phase0.export_interface_analyzer import export_interface_analyzer
        from workers.phase1.behavior_profile_synthesizer import behavior_profile_synthesizer
        from workers.phase1.function_boundary_detector import function_boundary_detector

        content = types.Content(
            role="user",
            parts=[types.Part(text=f"分析样本: {sample_project_name}, 导出目录: {sample_export_dir}")]
        )
        for event in runner.run(user_id="analyst_001", session_id=session.id, new_message=content):
            token_report.add_event_usage(event)

        # Persist Worker outputs + run Extractor after workflow completes
        for worker, atype in [
            (string_artifact_analyst, "strings"),
            (api_behavior_profiler, "api"),
            (export_interface_analyzer, "exports"),
        ]:
            raw = session.state.get(worker.output_key, {})
            if raw:
                await _persist_worker_output(worker, raw, atype, sample_project_name, token_report)

        bb_checkpoint("phase0_complete", sample_project_name)

        for worker, atype in [
            (behavior_profile_synthesizer, "behavior"),
            (function_boundary_detector, "functions"),
        ]:
            raw = session.state.get(worker.output_key, {})
            if raw:
                await _persist_worker_output(worker, raw, atype, sample_project_name, token_report)

        bb_checkpoint("phase1_complete", sample_project_name)
        bb_checkpoint("phase2_complete", sample_project_name)

    return runner, session_service, [], token_report


async def _persist_worker_output(worker, raw_output, artifact_type, project_name, token_report):
    """Save artifact, run extractor, save summary."""
    raw_output = coerce_state_dict(raw_output)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    prefix = "p0" if artifact_type in ("strings", "api", "exports") else "p1"
    artifact_name = f"{prefix}_{worker.name}_{timestamp}"

    bb_write_artifact(artifact_name, raw_output, project_name)

    # Run extractor
    extract_prompt = build_extraction_prompt(raw_output, artifact_type)
    extractor_service = InMemorySessionService()
    extractor_session = await extractor_service.create_session(
        app_name="extractor", user_id="system", session_id=f"extract_{artifact_name}",
    )
    extractor_runner = Runner(agent=extractor_agent, app_name="extractor", session_service=extractor_service)
    extractor_content = types.Content(role="user", parts=[types.Part(text=extract_prompt)])

    summary_output = None
    for ex_event in extractor_runner.run(user_id="system", session_id=extractor_session.id, new_message=extractor_content):
        token_report.add_event_usage(ex_event)
        if ex_event.is_final_response() and ex_event.content and ex_event.content.parts:
            summary_output = ex_event.content.parts[0].text

    if summary_output:
        try:
            summary_data = json.loads(summary_output)
            bb_write_summary(f"{artifact_type}_summary", summary_data, project_name)
        except json.JSONDecodeError:
            bb_log_event("extractor_parse_failed", {"worker": worker.name, "type": artifact_type}, project_name)
