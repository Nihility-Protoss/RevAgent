"""LangGraph node factory and business nodes.

Replaces workers/orchestrator.py (ADK dynamic workflow + handwritten Runners)
and agent.py (_persist_worker_output / extractor Runner loops).
"""
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from langchain.chat_models import init_chat_model
from langchain_core.messages.utils import convert_to_messages, count_tokens_approximately
from langchain_core.runnables import RunnableConfig

from config import cfg, cfg_int
from state import AnalysisState
from tools.blackboard_tools import (
    _now_iso,
    bb_checkpoint,
    bb_has_artifact,
    bb_list_summaries,
    bb_load_checkpoint,
    bb_log_event,
    bb_read_summary,
    bb_write_artifact,
    bb_write_summary,
    board_path,
    load_function_data,
)
from tools.file_loaders import detect_sample_type, pre_extract_sample
from workers.extractor import build_extraction_prompt
from workers.knowledge import KNOWLEDGE_REGISTRY, load_knowledge, match_guides
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt
from workers.phase4.synthesis_agent import AGGREGATOR_PROMPT, SHARD_SYNTHESIS_PROMPT
from workers.specs import WorkerSpec

# === LLM 构造（环境变量与 ADK 版保持一致）===

_LLM = None


def get_llm():
    """Return the shared chat model (config.yaml > env vars > defaults)."""
    global _LLM
    if _LLM is None:
        load_dotenv()
        # 思考模式与 create_agent 的强制 tool_choice（结构化输出）不兼容，
        # 默认关闭；需要思考模式时在 config.yaml 设 llm.thinking=enabled。
        _LLM = init_chat_model(
            cfg("llm.model", env="MODEL", default="deepseek-flash"),
            model_provider="openai",
            api_key=cfg("llm.api_key", env="API_KEY"),
            base_url=cfg("llm.base_url", env="BASE_URL", default="https://api.deepseek.com/v1"),
            temperature=0,
            max_retries=3,
            extra_body={"thinking": {"type": cfg("llm.thinking", env="THINKING", default="disabled")}},
        )
    return _LLM


def set_llm(llm) -> None:
    """Inject a model instance (used by tests to run offline)."""
    global _LLM
    _LLM = llm


# === 上下文预算（所有 agent 共享 128k 上限）===

def max_context_tokens() -> int:
    """单次 LLM 调用的输入 token 上限（config.yaml llm.max_context_tokens，默认 128k）。"""
    return cfg_int("llm.max_context_tokens", env="MAX_CONTEXT_TOKENS", default=128000)


# ReAct 循环内历史超过该阈值即触发摘要压缩（留 ~25% 余量给输出与系统提示）
def _summary_trigger_tokens() -> int:
    return int(max_context_tokens() * 0.75)


def enforce_context_budget(messages: list) -> list:
    """Trim message contents so the total estimate fits the context budget.

    Strategy: truncate the longest message contents first (middle of the text,
    keeping head and tail); raise RuntimeError if still over budget.
    """
    budget = max_context_tokens()
    normalized = convert_to_messages(messages)

    for _round in range(3):
        total = count_tokens_approximately(normalized)
        if total <= budget:
            return normalized

        # 估算每条约消息的 token，用于定位可截断的大消息
        per_msg = [count_tokens_approximately([m]) for m in normalized]
        excess = total - budget
        # 从大到小截断，正文保留头尾各一半
        order = sorted(range(len(normalized)), key=lambda i: per_msg[i], reverse=True)
        for i in order:
            if excess <= 0:
                break
            content = normalized[i].content
            if not isinstance(content, str):
                continue
            # 保底留 ~50 tokens（头尾各约 100 字符），其余都可截掉
            max_cut = max(per_msg[i] - 50, 0)
            # 过切 20% + 16 tokens，覆盖截断标记与估算误差，避免多轮不收敛
            cut = min(int(excess * 1.2) + 16, max_cut)
            if cut <= 0:
                continue
            keep_chars = max(len(content) - cut * 4, 200)
            half = keep_chars // 2
            normalized[i] = normalized[i].model_copy(update={
                "content": content[:half] + "\n...[内容过长已截断]...\n" + content[-half:],
            })
            excess -= cut

    final = count_tokens_approximately(normalized)
    if final > budget:
        raise RuntimeError(
            f"prompt 估算 {final} tokens 超过上下文上限 {budget}，"
            "截断后仍无法容纳，请减小输入分片或调高 MAX_CONTEXT_TOKENS"
        )
    return normalized


async def invoke_guarded(model, messages: list, config: Optional[RunnableConfig] = None):
    """ainvoke with context-budget enforcement (128k by default)."""
    return await model.ainvoke(enforce_context_budget(messages), config=config)


# === 通用辅助 ===

def parse_json_loose(text: Any) -> dict:
    """Best-effort JSON parse of model output; never raises."""
    if isinstance(text, dict):
        return text
    if not isinstance(text, str):
        return {"status": "parse_failed", "raw": str(text), "parse_error": True}
    stripped = text.strip()
    # 去掉可能的 markdown 代码围栏
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = [l for l in lines if not l.strip().startswith("```")]
        stripped = "\n".join(lines).strip()
    try:
        data = json.loads(stripped)
        return data if isinstance(data, dict) else {"status": "success", "data": data}
    except (json.JSONDecodeError, ValueError):
        return {"status": "parse_failed", "raw": text, "parse_error": True}


# output_key -> (artifact_type, artifact 文件名前缀)
_ARTIFACT_TYPES = {
    "string_analysis": ("strings", "p0"),
    "api_behavior_analysis": ("api", "p0"),
    "export_interface_analysis": ("exports", "p0"),
    "behavior_profile": ("behavior", "p1"),
    "function_boundary_analysis": ("functions", "p1"),
}


async def run_extraction(
    artifact: dict,
    artifact_type: str,
    summary_name: str,
    project_name: str,
    llm=None,
    config: Optional[RunnableConfig] = None,
) -> Optional[dict]:
    """Run the summary extractor as a plain LLM call and persist the summary."""
    model = llm or get_llm()
    prompt = build_extraction_prompt(artifact, artifact_type)
    resp = await invoke_guarded(model, [("user", prompt)], config=config)
    data = parse_json_loose(getattr(resp, "content", resp))
    if data.get("parse_error"):
        bb_log_event(
            "extractor_parse_failed",
            {"type": artifact_type, "summary": summary_name},
            project_name,
        )
        return None
    bb_write_summary(summary_name, data, project_name)
    return data


# === Worker 节点工厂（替代 ADK LlmAgent + output_key）===

def make_worker_node(spec: WorkerSpec, llm=None):
    """Compile a WorkerSpec into a LangGraph node function.

    The model is resolved lazily on first node execution so that building the
    graph (e.g. to inspect its topology) never requires API credentials.
    """
    _cache: dict = {}

    def _agent():
        if "agent" not in _cache:
            _cache["model"] = llm or get_llm()
            _cache["agent"] = create_agent(
                model=_cache["model"],
                tools=list(spec.tools),
                system_prompt=spec.instruction,
                response_format=spec.output_schema,
                # ReAct 历史接近上下文上限（128k 的 75%）时自动摘要压缩
                middleware=[
                    SummarizationMiddleware(
                        _cache["model"],
                        trigger=("tokens", _summary_trigger_tokens()),
                        keep=("messages", 20),
                    )
                ],
            )
        return _cache["agent"]

    async def node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        project = state["sample_project_name"]
        task = (
            f"分析样本: {project}, "
            f"导出目录: {state.get('sample_export_dir', '')}"
        )
        result = await _agent().ainvoke({"messages": [("user", task)]}, config=config)
        structured = result.get("structured_response")
        if structured is not None:
            payload = (
                structured.model_dump() if hasattr(structured, "model_dump") else dict(structured)
            )
        else:
            payload = parse_json_loose(result["messages"][-1].content)

        type_info = _ARTIFACT_TYPES.get(spec.output_key)
        if type_info and isinstance(payload, dict):
            artifact_type, prefix = type_info
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            bb_write_artifact(f"{prefix}_{spec.name}_{timestamp}", payload, project)
            await run_extraction(
                payload, artifact_type, f"{artifact_type}_summary", project, _cache["model"], config
            )
        return {spec.output_key: payload}

    node.__name__ = spec.name
    return node


# === Phase -1: 预提取（纯函数节点）===

def pre_extract_node(state: AnalysisState) -> dict:
    """Run Phase -1 pre-extraction into the blackboard (skipped on resume)."""
    project = state["sample_project_name"]
    existing = bb_load_checkpoint(project)
    if state.get("resume") and existing is not None:
        bb_log_event(
            "run_start",
            {"mode": "resume", "phase": existing.get("current_phase")},
            project,
        )
        return {}
    bb_log_event("run_start", {"mode": "fresh"}, project)
    result = pre_extract_sample(state["sample_export_dir"], project)
    if result["status"] != "success":
        raise RuntimeError(f"Pre-extraction failed: {result.get('error')}")

    # 样本类型永远 auto：由预提取节点根据导出产物判定并写入图状态
    type_result = detect_sample_type(state["sample_export_dir"])
    sample_type = type_result.get("sample_type", "unknown")
    bb_log_event(
        "sample_type_detected",
        {
            "sample_type": sample_type,
            "confidence": type_result.get("confidence"),
            "indicators": type_result.get("indicators", []),
        },
        project,
    )

    bb_checkpoint("pre_extract_complete", project)
    return {"sample_type": sample_type}


# === 知识路由（纯函数节点，逻辑照搬原 orchestrator.resolve_active_guides）===

def resolve_active_guides(project_name: str, arch_detection: Optional[dict] = None) -> dict:
    """Resolve which knowledge guides are active for this sample.

    Uses the provided arch_detection when given (Phase 0 string analysis in
    graph state); otherwise reads it from strings_summary on the blackboard.
    Matches it against the knowledge registry and persists the result to
    meta/active_guides.json. Never raises: on any failure falls back to the
    windows_pe baseline.
    """
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
        meta_dir = board_path(project_name, "meta")
        os.makedirs(meta_dir, exist_ok=True)
        with open(os.path.join(meta_dir, "active_guides.json"), "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "guides": guides}
    return doc


def resolve_guides_node(state: AnalysisState) -> dict:
    """Resolve active knowledge guides from Phase 0 arch_detection."""
    string_analysis = state.get("string_analysis") or {}
    arch = string_analysis.get("arch_detection") if isinstance(string_analysis, dict) else None
    resolve_active_guides(state["sample_project_name"], arch_detection=arch)
    return {}


def _load_active_guides_text(project_name: str) -> str:
    """Concatenate full text of all active guides for prompt injection."""

    def _fallback() -> str:
        result = load_knowledge("__active__", project_name)
        return result.get("content", "") if result.get("status") == "success" else ""

    meta_path = board_path(project_name, "meta", "active_guides.json")
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


# === HITL 审批门（CLI input() 实现，interrupt() 留待 Step 2）===

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


def build_review_message(state: dict) -> str:
    """Build human-readable review message from graph state."""
    behavior_profile = state.get("behavior_profile") or {}
    string_analysis = state.get("string_analysis") or {}
    api_behavior = state.get("api_behavior_analysis") or {}
    function_boundary = state.get("function_boundary_analysis") or {}

    behavior_type = behavior_profile.get("behavior_profile", {}).get("primary_type", "Unknown")
    confidence = behavior_profile.get("behavior_profile", {}).get("confidence", "low")

    high_risk_strings = len([
        s for s in string_analysis.get("suspicious_patterns", [])
        if isinstance(s, dict) and s.get("risk_level") == "high"
    ])
    high_risk_apis = len([
        api for api in api_behavior.get("suspicious_apis", [])
        if isinstance(api, dict) and api.get("threat_category") in ["进程注入", "持久化", "网络通信"]
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


def parse_approval_reply(text: str) -> tuple[str, Optional[list[str]]]:
    """Parse CONFIRM or MODIFY reply from human reviewer."""
    text_stripped = text.strip()
    if text_stripped.upper() == "CONFIRM":
        return ("confirm", None)
    if text_stripped.upper().startswith("MODIFY "):
        addrs = [a.strip() for a in text_stripped[7:].split(",") if a.strip()]
        return ("modify", addrs)
    return ("invalid", None)


def prompt_human(message: str) -> str:
    """Read one reply line from the analyst (module-level for test monkeypatching)."""
    return input(message)


def approval_gate_node(state: AnalysisState) -> dict:
    """Phase 2→3 human approval gate (CLI). 3 次无效回复后默认 CONFIRM 放行。"""
    print(build_review_message(state))
    max_attempts = 3
    for attempt in range(max_attempts):
        reply = prompt_human("请回复 CONFIRM 或 MODIFY <addr1>,<addr2>,...: ")
        decision, addrs = parse_approval_reply(reply)
        if decision == "confirm":
            return {"phase2_human_decision": "CONFIRM"}
        if decision == "modify":
            return {
                "phase2_human_decision": reply.strip(),
                "human_approved_functions": addrs,
            }
        print(f"[ERROR] 无法识别回复: {reply.strip()}，请使用 CONFIRM 或 MODIFY 格式。")
    return {"phase2_human_decision": "CONFIRM (default after max attempts)"}


# === Phase 3: 函数级深度分析（串行循环，Send 并行留待 Step 3）===

def make_phase3_node(llm=None):
    """Build the Phase 3 per-function deep-analysis node (serial loop)."""

    async def phase3_deep_analysis_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm()
        project = state["sample_project_name"]
        function_boundary = state.get("function_boundary_analysis") or {}
        all_candidates = function_boundary.get("candidates", [])

        human_addrs = state.get("human_approved_functions")
        if human_addrs:
            candidates = [c for c in all_candidates if c.get("func_addr") in human_addrs]
        else:
            candidates = [c for c in all_candidates if c.get("analysis_priority", 0) >= 7][:20]

        refs: list[dict] = []
        if not candidates:
            bb_log_event("phase3_skipped", {"reason": "no_candidates"}, project)
            return {"func_analysis_refs": refs}

        guides_text = _load_active_guides_text(project)

        for candidate in candidates:
            addr = candidate.get("func_addr")
            name = candidate.get("func_name", f"func_{addr}")

            # 幂等：重跑跳过已完成的函数
            if bb_has_artifact(f"phase3_func_{addr}", project):
                refs.append({"addr": addr, "skipped": True})
                continue

            func_data = load_function_data(addr, state["sample_export_dir"])
            if func_data.get("status") != "success":
                refs.append({"addr": addr, "status": "load_failed"})
                continue

            prompt = build_func_analysis_prompt(
                addr, name, func_data,
                guides=guides_text,
                project_name=project,
            )
            resp = await invoke_guarded(model, [("user", prompt)], config=config)
            artifact = parse_json_loose(getattr(resp, "content", resp))
            bb_write_artifact(f"phase3_func_{addr}", artifact, project)

            summary = await run_extraction(
                artifact, "function_deep", f"phase3_funcs/func_{addr}", project, model, config
            )
            refs.append({"addr": addr, "summary": summary})
            bb_checkpoint(f"phase3_progress_{addr}", project)

        return {"func_analysis_refs": refs}

    return phase3_deep_analysis_node


# === Phase 4: 综合报告（Map-Reduce，分片串行为小模型稳定性保留）===

def _read_phase01_summaries(project_name: str) -> dict:
    """Read the five Phase 0/1 summaries from the blackboard."""
    return {
        "p0_strings": bb_read_summary("strings_summary", project_name),
        "p0_api": bb_read_summary("api_summary", project_name),
        "p0_exports": bb_read_summary("exports_summary", project_name),
        "p1_behavior": bb_read_summary("behavior_summary", project_name),
        "p1_functions": bb_read_summary("functions_summary", project_name),
    }


def _summary_data(summary: dict) -> dict:
    return summary.get("data") if summary.get("status") == "success" else {}


def make_shard_synthesis_node(llm=None):
    """Build the Phase 4 map node: shard synthesis over suspicious functions."""

    async def shard_synthesis_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm()
        project = state["sample_project_name"]
        s = _read_phase01_summaries(project)
        p3_summaries = bb_list_summaries("phase3_funcs/", project)

        # 只保留有可疑行为的函数，按优先级排序，最多 15 个
        suspicious = [x for x in p3_summaries if x.get("suspicious_behaviors")]
        suspicious.sort(key=lambda x: x.get("analysis_priority", 0), reverse=True)
        suspicious = suspicious[:15]

        shard_size = 5
        shards = [suspicious[i:i + shard_size] for i in range(0, len(suspicious), shard_size)]
        shard_reports: list[dict] = []

        for idx, shard in enumerate(shards):
            shard_context = {
                "phase0": {
                    "strings": _summary_data(s["p0_strings"]),
                    "api": _summary_data(s["p0_api"]),
                    "exports": _summary_data(s["p0_exports"]),
                },
                "phase1": {
                    "behavior": _summary_data(s["p1_behavior"]),
                    "functions": _summary_data(s["p1_functions"]),
                },
                "phase3_shard": shard,
                "shard_id": idx + 1,
            }
            resp = await invoke_guarded(
                model,
                [
                    ("system", SHARD_SYNTHESIS_PROMPT),
                    ("user", json.dumps(shard_context, ensure_ascii=False)),
                ],
                config=config,
            )
            report = parse_json_loose(getattr(resp, "content", resp))
            if report.get("parse_error"):
                report["shard_id"] = idx + 1
                report["status"] = "parse_failed"
            shard_reports.append(report)

        return {"shard_reports": shard_reports}

    return shard_synthesis_node


def make_aggregator_node(llm=None):
    """Build the Phase 4 reduce node: aggregate shard reports into final report."""

    async def aggregator_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm()
        project = state["sample_project_name"]
        s = _read_phase01_summaries(project)

        aggregate_context = {
            "shard_reports": state.get("shard_reports", []),
            "phase0_summary": {
                "strings": _summary_data(s["p0_strings"]),
                "api": _summary_data(s["p0_api"]),
                "exports": _summary_data(s["p0_exports"]),
            },
            "phase1_summary": {
                "behavior": _summary_data(s["p1_behavior"]),
            },
        }
        resp = await invoke_guarded(
            model,
            [
                ("system", AGGREGATOR_PROMPT),
                ("user", json.dumps(aggregate_context, ensure_ascii=False)),
            ],
            config=config,
        )
        report = parse_json_loose(getattr(resp, "content", resp))
        bb_write_summary("p4_final_report", report, project)
        bb_checkpoint("phase4_complete", project)
        return {"final_report_ref": "bb://summary/p4_final_report"}

    return aggregator_node
