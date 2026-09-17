import os
import sys

# Ensure project root is in Python path for ADK CLI imports
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from workers.orchestrator import (  # noqa: F401  (re-exports, tests migrate in Task 5)
    LLM_MODEL,
    _build_review_message,
    _load_active_guides_text,
    _parse_approval_reply,
    _parse_config_from_text,
    analysis_orchestrator,
    approval_fn,
    resolve_active_guides,
    root_agent,
    setup_fn,
    setup_node,
)
# Backward-compat alias: the helper now lives in tools.state_utils and is
# consumed by orchestrator; test_integration still imports it from agent.
from tools.state_utils import extract_arch_detection as _extract_arch_detection  # noqa: F401

from typing import Dict, List, Any, Optional
from collections.abc import AsyncGenerator
from pathlib import Path
from dotenv import load_dotenv

from tools.token_stats import AnalysisTokenReport, StageTokenStats

from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.events.request_input import RequestInput
from google.adk.workflow._function_node import FunctionNode
from google.adk.workflow import node
from google.genai import types
from google.adk.models.lite_llm import LiteLlm

# Load environment variables
load_dotenv()


# === Runtime Entry ===
def run_analysis(
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

    session = session_service.create_session(
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


# Backward compatibility: expose root_agent for ADK CLI


# === Phase -1 to Phase 2 Orchestration with Blackboard ===

import asyncio
import json
from datetime import datetime, timezone
from tools.blackboard_tools import (
    _now_iso,
    bb_checkpoint, bb_has_artifact, bb_list_summaries, bb_load_checkpoint, bb_log_event,
    bb_read_extract, bb_read_summary, bb_write_artifact, bb_write_summary,
    load_function_data,
)
from tools.file_loaders import pre_extract_sample
from workers.extractor import build_extraction_prompt, extractor_agent
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt, function_deep_analyzer
from workers.phase4.synthesis_agent import synthesis_agent


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
    session = session_service.create_session(
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

    # Phase 0/1/2: Run Workflow (Static Graph handles parallel execution)
    if state.get("current_phase") in ("pre_extract_complete", "phase0", "phase1", "phase2"):
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
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    prefix = "p0" if artifact_type in ("strings", "api", "exports") else "p1"
    artifact_name = f"{prefix}_{worker.name}_{timestamp}"

    bb_write_artifact(artifact_name, raw_output, project_name)

    # Run extractor
    extract_prompt = build_extraction_prompt(raw_output, artifact_type)
    extractor_service = InMemorySessionService()
    extractor_session = extractor_service.create_session(
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


async def phase3_function_analysis(
    runner, session, project_name, sample_export_dir, token_report
):
    """Phase 3: Dynamic per-function deep analysis loop."""
    from google.genai import types

    # Read approved functions from Phase 2 decision
    decision_summary = bb_read_summary("p2_decision", project_name)
    if decision_summary.get("status") != "success":
        bb_log_event("phase3_skipped", {"reason": "no_decision"}, project_name)
        return []

    pending = decision_summary["data"].get("approved_functions", [])
    pending.sort(key=lambda x: x.get("priority", 99))

    all_events = []

    for func in pending:
        addr = func["addr"]
        name = func.get("name", f"func_{addr}")

        # Skip already analyzed (resume support)
        if bb_has_artifact(f"phase3_func_{addr}", project_name):
            continue

        # Load function data via Tool
        func_data = load_function_data(addr, sample_export_dir)
        if func_data.get("status") != "success":
            bb_log_event("phase3_func_load_failed", {"addr": addr}, project_name)
            continue

        # Build analyzer for this function
        prompt = build_func_analysis_prompt(addr, name, func_data)
        analyzer = LlmAgent(
            name=f"func_analyzer_{addr}",
            model=LLM_MODEL,
            instruction=prompt,
            output_key=f"func_analysis_{addr}",
        )

        # Run analyzer
        func_session_service = InMemorySessionService()
        func_session = func_session_service.create_session(
            app_name="func_analysis", user_id="system",
            session_id=f"func_{addr}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        )
        func_runner = Runner(agent=analyzer, app_name="func_analysis", session_service=func_session_service)
        func_content = types.Content(role="user", parts=[types.Part(text=prompt)])

        func_output = None
        for event in func_runner.run(user_id="system", session_id=func_session.id, new_message=func_content):
            token_report.add_event_usage(event)
            all_events.append(event)
            if event.is_final_response() and event.content and event.content.parts:
                func_output = event.content.parts[0].text

        # Save artifact
        if func_output:
            try:
                artifact = json.loads(func_output)
            except json.JSONDecodeError:
                artifact = {"raw": func_output, "parse_error": True}
            bb_write_artifact(f"phase3_func_{addr}", artifact, project_name)

            # Extract summary via Extractor
            extract_prompt = build_extraction_prompt(artifact, "function_deep")
            extractor_service = InMemorySessionService()
            extractor_session = extractor_service.create_session(
                app_name="extractor", user_id="system", session_id=f"extract_func_{addr}",
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
                    bb_write_summary(f"phase3_funcs/func_{addr}", summary_data, project_name)
                except json.JSONDecodeError:
                    bb_log_event("extractor_parse_failed", {"worker": f"func_{addr}"}, project_name)

        bb_checkpoint(f"phase3_progress_{addr}", project_name)

    bb_checkpoint("phase3_complete", project_name)
    return all_events


async def phase4_final_synthesis(project_name, token_report):
    """Phase 4: Aggregate all summaries into final report."""
    from google.genai import types

    p0_strings = bb_read_summary("strings_summary", project_name)
    p0_api = bb_read_summary("api_summary", project_name)
    p0_exports = bb_read_summary("exports_summary", project_name)
    p1_behavior = bb_read_summary("behavior_summary", project_name)
    p1_functions = bb_read_summary("functions_summary", project_name)
    p3_summaries = bb_list_summaries("phase3_funcs/", project_name)

    context = {
        "phase0": {
            "strings": p0_strings.get("data") if p0_strings.get("status") == "success" else {},
            "api": p0_api.get("data") if p0_api.get("status") == "success" else {},
            "exports": p0_exports.get("data") if p0_exports.get("status") == "success" else {},
        },
        "phase1": {
            "behavior": p1_behavior.get("data") if p1_behavior.get("status") == "success" else {},
            "functions": p1_functions.get("data") if p1_functions.get("status") == "success" else {},
        },
        "phase3": {
            "total_analyzed": len(p3_summaries),
            "suspicious_findings": [s for s in p3_summaries if s.get("suspicious")],
        },
    }

    synth_session = InMemorySessionService()
    synth_session_obj = synth_session.create_session(
        app_name="synthesis", user_id="system", session_id=f"synth_{project_name}",
    )
    synth_runner = Runner(agent=synthesis_agent, app_name="synthesis", session_service=synth_session)
    synth_content = types.Content(role="user", parts=[types.Part(text=json.dumps(context, ensure_ascii=False))])

    report_output = None
    for event in synth_runner.run(user_id="system", session_id=synth_session_obj.id, new_message=synth_content):
        token_report.add_event_usage(event)
        if event.is_final_response() and event.content and event.content.parts:
            report_output = event.content.parts[0].text

    if report_output:
        try:
            report = json.loads(report_output)
            bb_write_summary("p4_final_report", report, project_name)
        except json.JSONDecodeError:
            bb_write_summary("p4_final_report", {"raw": report_output, "parse_error": True}, project_name)

    bb_checkpoint("phase4_complete", project_name)


async def _run_worker_with_retry(
    runner, session, worker, content, max_retries=3, timeout_sec=60
):
    """Run a worker with retry and timeout handling.

    Args:
        runner: ADK Runner instance.
        session: ADK Session.
        worker: The worker agent (for identification/logging).
        content: The user message content.
        max_retries: Maximum number of retry attempts.
        timeout_sec: Timeout per attempt in seconds.

    Returns:
        List of events from the successful run.
    """
    import asyncio

    last_exception = None
    for attempt in range(1, max_retries + 1):
        try:
            events = []
            for event in runner.run(
                user_id="analyst_001",
                session_id=session.id,
                new_message=content,
            ):
                events.append(event)
                if event.is_final_response():
                    return events
            return events
        except asyncio.TimeoutError:
            last_exception = "timeout"
            if attempt == max_retries:
                raise RuntimeError(f"Worker {worker.name} timed out after {max_retries} retries")
            await asyncio.sleep(1 * attempt)  # Exponential-ish backoff
        except Exception as e:
            last_exception = str(e)
            if attempt == max_retries:
                raise RuntimeError(f"Worker {worker.name} failed after {max_retries} retries: {e}")
            await asyncio.sleep(1 * attempt)
