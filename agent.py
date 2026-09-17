import os
import sys

# Ensure project root is in Python path for ADK CLI imports
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from typing import Dict, List, Any, Optional
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.events.request_input import RequestInput
from google.adk.workflow._function_node import FunctionNode
from google.adk.workflow import node
from google.genai import types
from google.adk.models.lite_llm import LiteLlm

# Import workers
from workers.phase0.string_artifact_analyst import string_artifact_analyst
from workers.phase0.api_behavior_profiler import api_behavior_profiler
from workers.phase0.export_interface_analyzer import export_interface_analyzer
from workers.phase1.behavior_profile_synthesizer import behavior_profile_synthesizer
from workers.phase1.function_boundary_detector import function_boundary_detector

# Import callbacks
from callbacks.human_review import human_review_callback

# Import tools for registration
from tools.file_loaders import (
    load_strings,
    load_exports,
    load_imports,
    load_function_index,
    load_pe_info,
    detect_sample_type,
)
from tools.pe_utils import calculate_entropy
from tools.blackboard_tools import bb_read_summary, bb_read_extract
from workers.knowledge import load_knowledge as load_arch_guide

# Load environment variables
load_dotenv()

# === Tool Registry ===
ALL_TOOLS = [
    load_strings,
    load_exports,
    load_imports,
    load_function_index,
    load_pe_info,
    detect_sample_type,
    calculate_entropy,
    bb_read_summary,
    bb_read_extract,
    load_arch_guide,
]

# Bind tools to workers
string_artifact_analyst.tools = ALL_TOOLS
api_behavior_profiler.tools = ALL_TOOLS
export_interface_analyzer.tools = ALL_TOOLS
behavior_profile_synthesizer.tools = ALL_TOOLS
function_boundary_detector.tools = ALL_TOOLS


# === Phase 2: Scheduler Agent ===
SCHEDULER_INSTRUCTION = """你是恶意样本分析系统的中央调度者。你不直接执行任何样本分析工作，你的职责是协调各个专业分析 Worker 的工作流，在关键决策点触发人工审查，并整合各 Worker 的分析结果。

【当前阶段】
Phase 0（快速定性）和 Phase 1（行为定型+函数筛选）已完成。5 个 Worker 的摘要已写入黑板 summary 目录：
- strings_summary: 字符串取证分析摘要
- api_summary: API 行为画像摘要
- exports_summary: 导出表与接口分析摘要
- behavior_summary: 综合行为定型与架构推断摘要
- functions_summary: 函数边界检测与候选函数排序摘要

【你的任务】
1. 通过 bb_read_summary 读取上述 5 个 summary
2. 提取关键发现：
   - behavior_summary 中的行为定型结论（RAT/Stealer/Loader/Backdoor）
   - 各 summary 中的 high severity 发现
   - functions_summary 中的 Top 20 候选函数
3. 生成简洁的状态报告，写入 output_key="scheduler_decision"
4. 更新 session.state["analysis_phase"] = "initial_complete"

【重要约束】
- 你的输入是各 Worker 的 summary（通过 bb_read_summary 读取），不是完整 artifact
- 只做数据路由和状态管理，不做新的样本分析推理
- 所有判断必须基于 summary 中已有的结论，不基于"常见恶意软件模式"进行推断
- 如果某个 summary 缺失或 status=insufficient_data，在报告中明确标注

【输出格式】
输出严格 JSON 格式（最多2层嵌套）：
{
  "status": "success|insufficient_data",
  "phase": "initial_complete",
  "action": "AWAITING_HUMAN_REVIEW",
  "summary": {
    "behavior_type": "定型结果或 Unknown",
    "confidence": "high|medium|low",
    "high_risk_count": 高风险发现数量,
    "candidate_functions": 候选函数数量
  },
  "details": {
    "string_key_findings": ["字符串关键发现"],
    "api_key_findings": ["API关键发现"],
    "export_key_findings": ["导出表关键发现"],
    "top_candidates": ["前5个候选函数信息"]
  }
}
"""

# === LiteLLM Model Configuration ===
_raw_model = os.getenv("MODEL", "deepseek-flash")
# Ensure openai/ prefix for LiteLlm to route to OpenAI-compatible API
if "/" not in _raw_model:
    _raw_model = f"openai/{_raw_model}"

LLM_MODEL = LiteLlm(
    model=_raw_model,
    api_key=os.getenv("API_KEY"),
    api_base=os.getenv("BASE_URL", "https://api.deepseek.com/v1"),
)

# === Setup Helpers ===

def _build_setup_message(error: str | None = None) -> str:
    """Build the HITL configuration prompt message."""
    msg = (
        "================================================\n"
        "  [SETUP] 恶意样本分析系统 - 初始化配置\n"
        "================================================\n\n"
        "[DIR] IDA 导出目录路径 (必填):\n"
        "   包含 strings.txt / exports.txt / imports.txt / function_index.txt\n\n"
        "[NAME] 项目组存档名称 (必填):\n"
        "   用于命名 .blackboard 子目录和输出文件\n\n"
        "[WORK] 工作目录 (可选, 默认当前目录):\n"
        "   .blackboard/ 和过程文件将存放于此\n\n"
        "================================================\n\n"
        "请按以下格式回复:\n"
        "每行一个，或使用 '|' 分隔（推荐命令行）\n\n"
        "EXPORT_DIR=<完整路径>\n"
        "PROJECT_NAME=<名称>\n"
        "WORK_DIR=<路径>  (可选)\n\n"
        "例如 (多行):\n"
        "EXPORT_DIR=D:\\analysis\\sample_001_export\n"
        "PROJECT_NAME=sample_001\n"
        "WORK_DIR=D:\\analysis\\output\n\n"
        "例如 (单行，命令行推荐):\n"
        "EXPORT_DIR=D:\\analysis\\sample_001_export|PROJECT_NAME=sample_001|WORK_DIR=D:\\analysis\\output"
    )
    if error:
        msg += f"\n\n[ERROR] 错误: {error}\n请修正后重新提交。"
    return msg


def _parse_config_from_text(text: str) -> dict:
    """Parse EXPORT_DIR / PROJECT_NAME / WORK_DIR and validate EXPORT_DIR exists.

    Supports both multiline format (one key per line) and pipe-separated
    single-line format for CLI HITL where input() only reads one line.
    """
    config = {"export_dir": None, "project_name": None, "work_dir": "."}

    lines = text.strip().splitlines()
    # If no newline keys matched, fall back to pipe-separated single-line format.
    if len(lines) == 1 and "|" in lines[0]:
        lines = [p.strip() for p in lines[0].split("|") if p.strip()]

    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("EXPORT_DIR="):
            config["export_dir"] = line[len("EXPORT_DIR="):].strip()
        elif line.startswith("PROJECT_NAME="):
            config["project_name"] = line[len("PROJECT_NAME="):].strip()
        elif line.startswith("WORK_DIR="):
            config["work_dir"] = line[len("WORK_DIR="):].strip() or "."

    if not config["export_dir"]:
        raise ValueError("EXPORT_DIR is required")
    if not config["project_name"]:
        raise ValueError("PROJECT_NAME is required")

    export_path = Path(config["export_dir"])
    try:
        if not export_path.exists():
            raise ValueError(f"EXPORT_DIR does not exist: {config['export_dir']}")
        if not export_path.is_dir():
            raise ValueError(f"EXPORT_DIR is not a directory: {config['export_dir']}")
    except OSError as exc:
        raise ValueError(f"Cannot access EXPORT_DIR: {exc}") from exc

    return config


# === Setup Node (pure HITL; parsing lives in the orchestrator) ===

async def setup_node(ctx: Any, node_input: Any | None = None) -> AsyncGenerator[RequestInput, None]:
    """Yield a RequestInput to collect configuration via ADK CLI HITL.

    The parent dynamic-workflow node is responsible for parsing the reply and
    writing configuration into session.state.
    """
    error_msg = node_input if isinstance(node_input, str) else None
    yield RequestInput(
        message=_build_setup_message(error=error_msg),
        response_schema=str,
    )


setup_fn = FunctionNode(
    func=setup_node,
    name="setup",
    rerun_on_resume=False,
)


# === Approval Gate (HITL for Phase 2→3 transition) ===

APPROVAL_MESSAGE_TEMPLATE = """=== 恶意样本初步分析审查 ===

行为定型: {behavior_type} (置信度: {confidence})
高风险字符串指标: {high_risk_strings}
高风险 API 指标: {high_risk_apis}
候选函数: {candidate_count} / {total_funcs}

请审查以上分析结论，确认：
1. 行为定型是否合理
2. 候选函数列表是否需要调整（排除/补充）
3. 是否需要继续深入分析特定函数

回复格式:
- CONFIRM  (同意继续，使用推荐候选函数)
- MODIFY <addr1>,<addr2>,...  (指定要分析的函数地址列表，逗号分隔)

例如: MODIFY 0x401000,0x402000,0x403000
"""


def _build_review_message(state: dict) -> str:
    """Build human-readable review message from session state."""
    behavior_profile = state.get("behavior_profile", {})
    string_analysis = state.get("string_analysis", {})
    api_behavior = state.get("api_behavior_analysis", {})
    function_boundary = state.get("function_boundary_analysis", {})

    behavior_type = behavior_profile.get("behavior_profile", {}).get("primary_type", "Unknown")
    confidence = behavior_profile.get("behavior_profile", {}).get("confidence", "low")

    high_risk_strings = len([
        s for s in string_analysis.get("suspicious_patterns", [])
        if s.get("risk_level") == "high"
    ])
    high_risk_apis = len([
        api for api in api_behavior.get("suspicious_apis", [])
        if api.get("threat_category") in ["进程注入", "持久化", "网络通信"]
    ])

    candidates = function_boundary.get("candidates", [])[:20]
    total_funcs = function_boundary.get("total_functions", 0)

    return APPROVAL_MESSAGE_TEMPLATE.format(
        behavior_type=behavior_type,
        confidence=confidence,
        high_risk_strings=high_risk_strings,
        high_risk_apis=high_risk_apis,
        candidate_count=len(candidates),
        total_funcs=total_funcs,
    )


def _parse_approval_reply(text: str) -> tuple[str, list[str] | None]:
    """Parse CONFIRM or MODIFY reply from human reviewer."""
    text_stripped = text.strip()
    if text_stripped.upper() == "CONFIRM":
        return ("confirm", None)
    if text_stripped.upper().startswith("MODIFY "):
        addrs = [a.strip() for a in text_stripped[7:].split(",") if a.strip()]
        return ("modify", addrs)
    return ("invalid", None)


async def approval_node(ctx: Any, node_input: Any | None = None) -> AsyncGenerator[RequestInput, None]:
    """Yield RequestInput to collect human approval via ADK CLI HITL."""
    error_msg = node_input if isinstance(node_input, str) else None
    msg = _build_review_message(ctx.state)
    if error_msg:
        msg += f"\n\n[ERROR] 无法识别回复: {error_msg}\n请使用 CONFIRM 或 MODIFY <addr1>,<addr2>,... 格式回复。"
    yield RequestInput(message=msg, response_schema=str)


approval_fn = FunctionNode(
    func=approval_node,
    name="approval_gate",
    rerun_on_resume=False,
)


def resolve_active_guides(project_name: str, arch_detection: dict | None = None) -> dict:
    """Resolve which knowledge guides are active for this sample.

    Uses the provided arch_detection when given (Phase 0 string analysis in
    session state); otherwise reads it from strings_summary on the blackboard.
    Matches it against the knowledge registry and persists the result to
    meta/active_guides.json. Never raises: on any failure falls back to the
    windows_pe baseline.
    """
    import json
    import os

    from workers.knowledge import KNOWLEDGE_REGISTRY, match_guides

    if arch_detection is not None:
        arch = arch_detection or {}
    else:
        arch = {}
        try:
            summary = bb_read_summary("strings_summary", project_name)
            if summary.get("status") == "success":
                arch = (summary.get("data") or {}).get("arch_detection") or {}
        except Exception:
            arch = {}

    names = match_guides(arch)
    if not arch:
        bb_log_event(
            "active_guides_default_fallback",
            {"reason": "strings_summary or arch_detection missing"},
            project_name,
        )

    guides = [
        {
            "name": n,
            "title": KNOWLEDGE_REGISTRY[n].title,
            "priority": KNOWLEDGE_REGISTRY[n].priority,
        }
        for n in names
    ]
    doc = {
        "status": "success",
        "guides": guides,
        "arch_detection": arch,
        "resolved_at": _now_iso(),
    }
    try:
        meta_dir = os.path.join(".blackboard", project_name, "meta")
        os.makedirs(meta_dir, exist_ok=True)
        with open(os.path.join(meta_dir, "active_guides.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "guides": guides}
    return doc


def _load_active_guides_text(project_name: str) -> str:
    """Concatenate full text of all active guides for prompt injection."""
    import json
    import os

    from workers.knowledge import KNOWLEDGE_REGISTRY, load_knowledge

    def _fallback() -> str:
        result = load_knowledge("__active__", project_name)
        return result.get("content", "") if result.get("status") == "success" else ""

    meta_path = os.path.join(".blackboard", project_name, "meta", "active_guides.json")
    if not os.path.exists(meta_path):
        return _fallback()
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return _fallback()
    parts = []
    for g in doc.get("guides", []):
        name = g.get("name")
        if name not in KNOWLEDGE_REGISTRY:
            continue
        result = load_knowledge(name, project_name)
        if result.get("status") == "success":
            parts.append(f"=== {result['title']} ===\n{result['content']}")
    text = "\n\n".join(parts)
    return text if text else _fallback()


# === Dynamic Workflow Orchestrator ===

@node(name="analysis_orchestrator", rerun_on_resume=True)
async def analysis_orchestrator(ctx: Any, node_input: Any | None = None) -> Any:
    """Dynamic workflow that orchestrates setup HITL -> Phase 0 -> Phase 1 -> Phase 2 -> HITL -> Phase 3 -> Phase 4."""
    import asyncio

    # --- Setup: collect configuration via HITL if not already present ---
    max_attempts = 3
    error_msg = None
    for attempt in range(max_attempts):
        if ctx.state.get("sample_export_dir") and ctx.state.get("sample_project_name"):
            break

        user_text = await ctx.run_node(setup_fn, node_input=error_msg)
        if user_text:
            text = str(user_text).strip()
            try:
                config = _parse_config_from_text(text)
                ctx.state["sample_export_dir"] = config["export_dir"]
                ctx.state["sample_project_name"] = config["project_name"]
                ctx.state["output_base"] = config["work_dir"]
                error_msg = None
                break
            except ValueError as exc:
                error_msg = str(exc)
                if attempt == max_attempts - 1:
                    raise ValueError(f"Setup failed after {max_attempts} attempts: {exc}") from exc
                continue

    # --- Phase 0: Triage workers in parallel ---
    if not ctx.state.get("phase0_complete"):
        await asyncio.gather(
            ctx.run_node(string_artifact_analyst),
            ctx.run_node(api_behavior_profiler),
            ctx.run_node(export_interface_analyzer),
        )
        ctx.state["phase0_complete"] = True

    # --- Resolve active knowledge guides from Phase 0 arch_detection ---
    if not ctx.state.get("active_guides_resolved"):
        string_analysis = ctx.state.get("string_analysis") or {}
        arch_detection = (
            string_analysis.get("arch_detection")
            if isinstance(string_analysis, dict)
            else None
        )
        resolve_active_guides(ctx.state["sample_project_name"], arch_detection=arch_detection)
        ctx.state["active_guides_resolved"] = True

    # --- Phase 1: Deep analysis workers in parallel ---
    if not ctx.state.get("phase1_complete"):
        await asyncio.gather(
            ctx.run_node(behavior_profile_synthesizer),
            ctx.run_node(function_boundary_detector),
        )
        ctx.state["phase1_complete"] = True

    # --- Phase 2: Scheduler ---
    if not ctx.state.get("phase2_complete"):
        scheduler_result = await ctx.run_node(scheduler_agent)
        ctx.state["phase2_complete"] = True

    # --- HITL Gate: Phase 2→3 approval ---
    if not ctx.state.get("phase2_approved"):
        max_approval_attempts = 3
        approval_error = None
        for attempt in range(max_approval_attempts):
            user_reply = await ctx.run_node(approval_fn, node_input=approval_error)
            if user_reply:
                reply_text = str(user_reply).strip()
                decision, addrs = _parse_approval_reply(reply_text)
                if decision == "confirm":
                    ctx.state["phase2_approved"] = True
                    ctx.state["phase2_human_decision"] = "CONFIRM"
                    break
                elif decision == "modify":
                    ctx.state["phase2_approved"] = True
                    ctx.state["phase2_human_decision"] = reply_text
                    ctx.state["human_approved_functions"] = addrs
                    break
                else:
                    approval_error = f"无法识别回复: {reply_text}"
                    if attempt == max_approval_attempts - 1:
                        ctx.state["phase2_approved"] = True
                        ctx.state["phase2_human_decision"] = "CONFIRM (default after max attempts)"
                        break
                    continue

    # --- Phase 3: Dynamic per-function deep analysis ---
    if not ctx.state.get("phase3_complete"):
        # Resolve candidate functions
        function_boundary = ctx.state.get("function_boundary_analysis", {})
        all_candidates = function_boundary.get("candidates", [])

        human_addrs = ctx.state.get("human_approved_functions")
        if human_addrs:
            candidates = [c for c in all_candidates if c.get("func_addr") in human_addrs]
        else:
            candidates = [c for c in all_candidates if c.get("analysis_priority", 0) >= 7][:20]

        if not candidates:
            ctx.state["phase3_complete"] = True
            ctx.state["phase3_skipped_reason"] = "no_candidates"
        else:
            from workers.phase3.function_deep_analyzer import build_func_analysis_prompt
            from tools.blackboard_tools import bb_has_artifact, bb_write_artifact, bb_write_summary, bb_checkpoint
            from tools.file_loaders import load_function_data
            from workers.extractor import build_extraction_prompt, extractor_agent

            guides_text = _load_active_guides_text(ctx.state["sample_project_name"])

            for candidate in candidates:
                addr = candidate.get("func_addr")
                name = candidate.get("func_name", f"func_{addr}")

                if bb_has_artifact(f"phase3_func_{addr}", ctx.state["sample_project_name"]):
                    continue

                func_data = load_function_data(addr, ctx.state["sample_export_dir"])
                if func_data.get("status") != "success":
                    continue

                prompt = build_func_analysis_prompt(
                    addr, name, func_data,
                    guides=guides_text,
                    project_name=ctx.state["sample_project_name"],
                )
                analyzer = LlmAgent(
                    name=f"func_analyzer_{addr}",
                    model=LLM_MODEL,
                    instruction=prompt,
                    tools=[load_arch_guide],
                    output_key=f"func_analysis_{addr}",
                )

                func_session_service = InMemorySessionService()
                func_session = func_session_service.create_session(
                    app_name="func_analysis", user_id="system",
                    session_id=f"func_{addr}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                )
                func_runner = Runner(agent=analyzer, app_name="func_analysis", session_service=func_session_service)
                func_content = types.Content(role="user", parts=[types.Part(text=prompt)])

                func_output = None
                for event in func_runner.run(user_id="system", session_id=func_session.id, new_message=func_content):
                    if event.is_final_response() and event.content and event.content.parts:
                        func_output = event.content.parts[0].text

                if func_output:
                    try:
                        artifact = json.loads(func_output)
                    except json.JSONDecodeError:
                        artifact = {"status": "parse_failed", "raw": func_output, "parse_error": True}
                    bb_write_artifact(f"phase3_func_{addr}", artifact, ctx.state["sample_project_name"])

                    extract_prompt = build_extraction_prompt(artifact, "function_deep")
                    extractor_service = InMemorySessionService()
                    extractor_session = extractor_service.create_session(
                        app_name="extractor", user_id="system", session_id=f"extract_func_{addr}",
                    )
                    extractor_runner = Runner(agent=extractor_agent, app_name="extractor", session_service=extractor_service)
                    extractor_content = types.Content(role="user", parts=[types.Part(text=extract_prompt)])

                    summary_output = None
                    for ex_event in extractor_runner.run(user_id="system", session_id=extractor_session.id, new_message=extractor_content):
                        if ex_event.is_final_response() and ex_event.content and ex_event.content.parts:
                            summary_output = ex_event.content.parts[0].text

                    if summary_output:
                        try:
                            summary_data = json.loads(summary_output)
                            bb_write_summary(f"phase3_funcs/func_{addr}", summary_data, ctx.state["sample_project_name"])
                        except json.JSONDecodeError:
                            pass

                bb_checkpoint(f"phase3_progress_{addr}", ctx.state["sample_project_name"])

            ctx.state["phase3_complete"] = True

    # --- Phase 4: Final synthesis (Map-Reduce) ---
    if not ctx.state.get("phase4_complete"):
        project_name = ctx.state["sample_project_name"]

        p0_strings = bb_read_summary("strings_summary", project_name)
        p0_api = bb_read_summary("api_summary", project_name)
        p0_exports = bb_read_summary("exports_summary", project_name)
        p1_behavior = bb_read_summary("behavior_summary", project_name)
        p1_functions = bb_read_summary("functions_summary", project_name)
        p3_summaries = bb_list_summaries("phase3_funcs/", project_name)

        # Filter to suspicious functions only, max 15
        suspicious = [s for s in p3_summaries if s.get("suspicious_behaviors")]
        suspicious.sort(key=lambda x: x.get("analysis_priority", 0), reverse=True)
        suspicious = suspicious[:15]

        # Map: shard analysis (sequential for small model stability)
        shard_size = 5
        shards = [suspicious[i:i + shard_size] for i in range(0, len(suspicious), shard_size)]
        shard_reports = []

        for idx, shard in enumerate(shards):
            shard_context = {
                "phase0": {
                    "strings": p0_strings.get("data") if p0_strings.get("status") == "success" else {},
                    "api": p0_api.get("data") if p0_api.get("status") == "success" else {},
                    "exports": p0_exports.get("data") if p0_exports.get("status") == "success" else {},
                },
                "phase1": {
                    "behavior": p1_behavior.get("data") if p1_behavior.get("status") == "success" else {},
                    "functions": p1_functions.get("data") if p1_functions.get("status") == "success" else {},
                },
                "phase3_shard": shard,
                "shard_id": idx + 1,
            }

            shard_agent = LlmAgent(
                name=f"synthesis_shard_{idx + 1}",
                model=LLM_MODEL,
                instruction=SHARD_SYNTHESIS_PROMPT,
                output_key=f"shard_report_{idx + 1}",
            )
            shard_session = InMemorySessionService()
            shard_sess_obj = shard_session.create_session(
                app_name="synthesis", user_id="system", session_id=f"shard_{idx + 1}_{project_name}",
            )
            shard_runner = Runner(agent=shard_agent, app_name="synthesis", session_service=shard_session)
            shard_content = types.Content(role="user", parts=[types.Part(text=json.dumps(shard_context, ensure_ascii=False))])

            shard_output = None
            for event in shard_runner.run(user_id="system", session_id=shard_sess_obj.id, new_message=shard_content):
                if event.is_final_response() and event.content and event.content.parts:
                    shard_output = event.content.parts[0].text

            if shard_output:
                try:
                    shard_reports.append(json.loads(shard_output))
                except json.JSONDecodeError:
                    shard_reports.append({"shard_id": idx + 1, "status": "parse_failed", "raw": shard_output})

        # Reduce: aggregate all shards
        aggregate_context = {
            "shard_reports": shard_reports,
            "phase0_summary": {
                "strings": p0_strings.get("data") if p0_strings.get("status") == "success" else {},
                "api": p0_api.get("data") if p0_api.get("status") == "success" else {},
                "exports": p0_exports.get("data") if p0_exports.get("status") == "success" else {},
            },
            "phase1_summary": {
                "behavior": p1_behavior.get("data") if p1_behavior.get("status") == "success" else {},
            },
        }

        agg_session = InMemorySessionService()
        agg_sess_obj = agg_session.create_session(
            app_name="synthesis", user_id="system", session_id=f"agg_{project_name}",
        )
        agg_runner = Runner(agent=aggregator_agent, app_name="synthesis", session_service=agg_session)
        agg_content = types.Content(role="user", parts=[types.Part(text=json.dumps(aggregate_context, ensure_ascii=False))])

        report_output = None
        for event in agg_runner.run(user_id="system", session_id=agg_sess_obj.id, new_message=agg_content):
            if event.is_final_response() and event.content and event.content.parts:
                report_output = event.content.parts[0].text

        if report_output:
            try:
                report = json.loads(report_output)
                bb_write_summary("p4_final_report", report, project_name)
            except json.JSONDecodeError:
                bb_write_summary("p4_final_report", {"status": "parse_failed", "raw": report_output}, project_name)

        bb_checkpoint("phase4_complete", project_name)
        ctx.state["phase4_complete"] = True

    return {"status": "complete", "phase": "phase4_complete"}


# === Phase 4 Map-Reduce Prompts ===

SHARD_SYNTHESIS_PROMPT = """你是恶意样本综合分析专家（局部分析模式）。

你的任务是基于以下输入，生成一份局部综合分析报告。

输入：
- Phase 0/1 摘要（固定）
- Phase 3 函数深度分析摘要（最多5个函数）

规则：
1. 仅基于给定的函数摘要进行分析，不对未提供的函数做假设
2. 标识这5个函数中的关键可疑行为和 IOC
3. 输出格式为严格 JSON（最多2层嵌套）
4. 如果给定函数摘要为空或全部 status=insufficient_data → 输出 status=insufficient_data

输出字段：
{
  "shard_id": "编号",
  "status": "success|insufficient_data",
  "suspicious_functions_summary": ["函数地址: 关键发现"],
  "key_iocs": {"urls": [], "files": [], "registry": []},
  "behavior_pattern": "观察到的行为模式（仅基于这些函数）",
  "confidence": "high|medium|low",
  "uncertainties": ["不确定项"]
}
"""

AGGREGATOR_PROMPT = """你是恶意样本综合分析专家（汇总模式）。

你的任务是基于多个局部分析报告（shard_report），生成最终综合报告。

输入：
- N 个 shard_report
- Phase 0/1 总体摘要

规则：
1. 仅汇总各 shard 中重复出现或相互印证的发现
2. 如果不同 shard 的结论矛盾，在 uncertainties 中明确指出
3. malware_family 仅当 ≥2 个 shard 一致支持时才输出具体名称，否则输出 "Unknown"
4. confidence=high 仅当多个独立证据来源一致支持
5. 输出格式为严格 JSON（最多2层嵌套）
6. uncertainties 字段必须非空（至少1项）
7. 禁止基于"常见恶意软件行为模式"进行推断

输出字段：
{
  "status": "success|insufficient_data",
  "malware_family": "具体家族名或 Unknown",
  "confidence": "high|medium|low",
  "behavior_summary": "...",
  "key_iocs": {"urls": [], "files": [], "registry": []},
  "analyzed_functions": {"total": 10, "suspicious": 3, "key_functions": []},
  "breakpoint_recommendations": {"P0": [], "P1": [], "P2": []},
  "uncertainties": ["..."],
  "recommendations": ["..."]
}
"""

aggregator_agent = LlmAgent(
    name="synthesis_aggregator",
    model=LLM_MODEL,
    description="Aggregates shard reports into final comprehensive malware analysis report.",
    instruction=AGGREGATOR_PROMPT,
    output_key="final_report",
)

scheduler_agent = LlmAgent(
    name="scheduler",
    model=LLM_MODEL,
    description="Central scheduler that coordinates analysis workers and prepares summary for human review.",
    instruction=SCHEDULER_INSTRUCTION,
    # after_agent_callback removed — HITL now handled by orchestrator approval_fn
    output_key="scheduler_decision",
)

# Override model for all workers
string_artifact_analyst.model = LLM_MODEL
api_behavior_profiler.model = LLM_MODEL
export_interface_analyzer.model = LLM_MODEL
behavior_profile_synthesizer.model = LLM_MODEL
function_boundary_detector.model = LLM_MODEL
scheduler_agent.tools = ALL_TOOLS


# === Root Agent: dynamic workflow orchestrator ===
root_agent = analysis_orchestrator


# === Token Statistics Collector ===

@dataclass
class StageTokenStats:
    """Token usage stats for a single stage/node."""
    stage_name: str
    prompt_tokens: int = 0
    candidate_tokens: int = 0
    total_tokens: int = 0
    call_count: int = 0

    def add_usage(self, usage_metadata: Optional[Any]) -> None:
        """Add usage metadata from a single LLM call."""
        if usage_metadata is None:
            return
        self.prompt_tokens += getattr(usage_metadata, 'promptTokenCount', 0) or 0
        self.candidate_tokens += getattr(usage_metadata, 'candidatesTokenCount', 0) or 0
        self.total_tokens += getattr(usage_metadata, 'totalTokenCount', 0) or 0
        self.call_count += 1


@dataclass
class AnalysisTokenReport:
    """Complete token usage report for an analysis session."""
    sample_project_name: str
    stages: Dict[str, StageTokenStats] = field(default_factory=dict)
    total_prompt_tokens: int = 0
    total_candidate_tokens: int = 0
    total_tokens: int = 0
    total_llm_calls: int = 0

    def add_event_usage(self, event) -> None:
        """Process an ADK Event and extract token usage."""
        if not hasattr(event, 'usageMetadata') or event.usageMetadata is None:
            return

        # Determine stage from event node info
        stage_name = "unknown"
        if hasattr(event, 'nodeInfo') and event.nodeInfo:
            stage_name = event.nodeInfo.node_name or "unknown"

        if stage_name not in self.stages:
            self.stages[stage_name] = StageTokenStats(stage_name=stage_name)

        self.stages[stage_name].add_usage(event.usageMetadata)

        # Update totals
        self.total_prompt_tokens += getattr(event.usageMetadata, 'promptTokenCount', 0) or 0
        self.total_candidate_tokens += getattr(event.usageMetadata, 'candidatesTokenCount', 0) or 0
        self.total_tokens += getattr(event.usageMetadata, 'totalTokenCount', 0) or 0
        self.total_llm_calls += 1

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to dict."""
        return {
            "sample_project_name": self.sample_project_name,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_candidate_tokens": self.total_candidate_tokens,
            "total_tokens": self.total_tokens,
            "total_llm_calls": self.total_llm_calls,
            "stages": {
                name: {
                    "stage_name": s.stage_name,
                    "prompt_tokens": s.prompt_tokens,
                    "candidate_tokens": s.candidate_tokens,
                    "total_tokens": s.total_tokens,
                    "call_count": s.call_count,
                }
                for name, s in self.stages.items()
            },
        }

    def __str__(self) -> str:
        """Human-readable summary."""
        lines = [
            f"=== Token Usage Report: {self.sample_project_name} ===",
            f"Total LLM Calls: {self.total_llm_calls}",
            f"Total Prompt Tokens: {self.total_prompt_tokens:,}",
            f"Total Candidate Tokens: {self.total_candidate_tokens:,}",
            f"Total Tokens: {self.total_tokens:,}",
            "",
            "--- Per-Stage Breakdown ---",
        ]
        for name, stats in sorted(self.stages.items(), key=lambda x: -x[1].total_tokens):
            lines.append(
                f"  {stats.stage_name}: "
                f"{stats.call_count} calls, "
                f"{stats.total_tokens:,} tokens "
                f"(prompt: {stats.prompt_tokens:,}, candidate: {stats.candidate_tokens:,})"
            )
        lines.append("")
        return "\n".join(lines)


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
