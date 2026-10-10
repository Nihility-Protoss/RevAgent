"""LangGraph 节点工厂与业务节点。
"""
import asyncio
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from langchain.chat_models import init_chat_model
from langchain_core.messages.utils import convert_to_messages, count_tokens_approximately
from langchain_core.runnables import RunnableConfig
from langgraph.types import Send, interrupt

from candidate_guards import (
    DEFAULT_LIB_SIZE_MAX,
    DEFAULT_LIB_TAIL_RATIO,
    DEFAULT_LIB_XREF_THRESHOLD,
    DEFAULT_TOP_N,
    apply_candidate_guards,
    collect_export_addrs,
    function_addr_range,
    normalize_addr,
    synthesized_human_candidate,
)
from config import cfg, cfg_int
from observability import current_total_tokens
from state import ANALYSIS_TOPIC_VOCABULARY, AnalysisState, AnalysisTask, TaskManifest
from tools.blackboard_tools import (
    _now_iso,
    bb_checkpoint,
    bb_has_artifact,
    bb_list_artifacts,
    bb_list_summaries,
    bb_load_checkpoint,
    bb_log_event,
    bb_read_artifact,
    bb_read_extract,
    bb_read_summary,
    bb_write_artifact,
    bb_write_summary,
    board_path,
    load_function_data,
)
from tools.docs_tools import (
    docs_read_agent_reports,
    docs_write_agent_report,
    user_md_append_question,
    user_md_read,
    user_md_set_focus,
)
from tools.file_loaders import detect_sample_type, pre_extract_sample
from workers.extractor import build_extraction_prompt
from workers.knowledge import KNOWLEDGE_REGISTRY, load_knowledge, match_guides
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt
from workers.phase4.report_generator import REPORT_GENERATOR_PROMPT
from workers.phase4.synthesis_agent import AGGREGATOR_PROMPT, SHARD_SYNTHESIS_PROMPT
from workers.specs import WorkerSpec
from workers.topics.topic_prompts import build_topic_prompt

# === LLM 构造（环境变量与 ADK 版保持一致）===

_LLM = None
_LLM_LIGHT = None


def get_llm(tier: str = "strong"):
    """返回共享 chat model（优先级：config.yaml > 环境变量 > 默认值）。

    模型分层（B1）：tier="light" 为轻任务模型（Phase 0 triage / scheduler /
    验证 Worker / extractor 摘要），配置项 llm.light_model / light_base_url /
    light_api_key（环境变量 LIGHT_MODEL / LIGHT_BASE_URL / LIGHT_API_KEY 兜底）。
    light_model 缺省（None）时直接返回 strong 实例，零行为变化；
    light_base_url / light_api_key 缺省时分别回退主模型的 base_url / API_KEY。
    两个 tier 各自单例缓存。
    """
    global _LLM, _LLM_LIGHT
    if tier == "light":
        light_model = cfg("llm.light_model", env="LIGHT_MODEL")
        if not light_model:
            return get_llm("strong")
        if _LLM_LIGHT is None:
            load_dotenv()
            _LLM_LIGHT = init_chat_model(
                light_model,
                model_provider="openai",
                api_key=cfg("llm.light_api_key", env="LIGHT_API_KEY")
                        or cfg("llm.api_key", env="API_KEY"),
                base_url=cfg("llm.light_base_url", env="LIGHT_BASE_URL")
                         or cfg("llm.base_url", env="BASE_URL", default="https://api.deepseek.com/v1"),
                temperature=float(cfg("llm.temperature", env="TEMPERATURE", default="0")),
                max_retries=3,
                extra_body={"thinking": {"type": cfg("llm.thinking", env="THINKING", default="disabled")}},
            )
        return _LLM_LIGHT
    if _LLM is None:
        load_dotenv()
        # 思考模式与 create_agent 的强制 tool_choice（结构化输出）不兼容，
        # 默认关闭；需要思考模式时在 config.yaml 设 llm.thinking=enabled。
        # 温度可调：部分模型（如 Kimi Code）只允许特定温度值。
        _LLM = init_chat_model(
            cfg("llm.model", env="MODEL", default="deepseek-flash"),
            model_provider="openai",
            api_key=cfg("llm.api_key", env="API_KEY"),
            base_url=cfg("llm.base_url", env="BASE_URL", default="https://api.deepseek.com/v1"),
            temperature=float(cfg("llm.temperature", env="TEMPERATURE", default="0")),
            max_retries=3,
            extra_body={"thinking": {"type": cfg("llm.thinking", env="THINKING", default="disabled")}},
        )
    return _LLM


def set_llm(llm) -> None:
    """注入一个模型实例（供测试离线运行使用）；两个 tier 的单例一并替换，
    保证显式注入假模型时分层逻辑不生效。"""
    global _LLM, _LLM_LIGHT
    _LLM = llm
    _LLM_LIGHT = llm


# === 上下文预算（所有 agent 共享 128k 上限）===

def max_context_tokens() -> int:
    """单次 LLM 调用的输入 token 上限（config.yaml llm.max_context_tokens，默认 128k）。
    """
    return cfg_int("llm.max_context_tokens", env="MAX_CONTEXT_TOKENS", default=128000)


# ReAct 循环内历史超过该阈值即触发摘要压缩（留 ~25% 余量给输出与系统提示）
def _summary_trigger_tokens() -> int:
    return int(max_context_tokens() * 0.75)


def enforce_context_budget(messages: list) -> list:
    """裁剪消息内容，使总体估算量落在上下文预算内。

    策略：优先截断最长的消息内容（从文本中间截掉，保留头尾）；若仍超预算则抛出 RuntimeError。
    """
    budget = max_context_tokens()
    normalized = convert_to_messages(messages)

    for _round in range(3):
        total = count_tokens_approximately(normalized)
        if total <= budget:
            return normalized

        # 估算每条消息的 token，用于定位可截断的大消息
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


async def invoke_guarded(
    model,
    messages: list,
    config: Optional[RunnableConfig] = None,
    project_name: Optional[str] = None,
):
    """带上下文预算约束的 ainvoke（默认 128k）。

    project_name 提供时先过 token 预算闸门（analysis.token_budget 启用才生效）：
    项目累计用量超预算时 interrupt 挂起等人工放行。
    """
    if project_name is not None:
        _enforce_token_budget(project_name)
    return await model.ainvoke(enforce_context_budget(messages), config=config)


# === Token 预算闸门（analysis.token_budget，null/0=不启用）===

def token_budget() -> int:
    """单次分析的总 token 预算上限（0=不启用；env TOKEN_BUDGET 兜底）。"""
    return cfg_int("analysis.token_budget", env="TOKEN_BUDGET", default=0)


# 人工放行记录：project -> 已追加的放行额度（tokens）。
# interrupt 挂起后节点会从头重跑，模块级字典保证 resume 后步进不丢失；
# 每次放行追加一个步长（=原始预算），再次超限会再次挂起，可反复放行。
_BUDGET_ALLOWANCE: dict = {}


def _enforce_token_budget(state) -> None:
    """token 预算闸门：项目累计用量达到（基础预算 + 已放行额度）时 interrupt 挂起。

    参数接受 AnalysisState（取 sample_project_name）或项目名字符串。
    用量数据源是 observability 的模块级 callback 注册表；未启用（budget<=0）
    或项目未注册 callback（如未挂 TokenStatsCallback 的测试图）时直接放行。
    """
    budget = token_budget()
    if budget <= 0:
        return
    project = state["sample_project_name"] if isinstance(state, dict) else str(state)
    used = current_total_tokens(project)
    effective = budget + _BUDGET_ALLOWANCE.get(project, 0)
    if used < effective:
        return
    interrupt({
        "kind": "token_budget",
        "message": (
            f"token 用量 {used:,} 已达预算上限 {effective:,}（基础预算 {budget:,}）。"
            "回复任意内容（如 CONTINUE）放行一个预算步长后继续，或中止分析。"
        ),
        "used_tokens": used,
        "budget": budget,
        "effective_budget": effective,
    })
    # 人工恢复后走到这里：追加一个步长，用量再涨满一个步长会再次挂起
    _BUDGET_ALLOWANCE[project] = _BUDGET_ALLOWANCE.get(project, 0) + budget


# === 通用辅助 ===

def parse_json_loose(text: Any) -> dict:
    """尽力解析模型输出的 JSON，永不抛异常。
    """
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
    "verification_report": ("verification", "p3v"),
}


async def run_extraction(
    artifact: dict,
    artifact_type: str,
    summary_name: str,
    project_name: str,
    llm=None,
    config: Optional[RunnableConfig] = None,
) -> Optional[dict]:
    """以普通 LLM 调用方式运行 summary extractor，并持久化 summary。

    extractor 是轻任务：llm 缺省时走 light tier（未配置 light 模型则回退主模型）。
    """
    model = llm or get_llm("light")
    prompt = build_extraction_prompt(artifact, artifact_type)
    resp = await invoke_guarded(model, [("user", prompt)], config=config, project_name=project_name)
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
    """把一个 WorkerSpec 编译为 LangGraph 节点函数。

    模型分层：Worker 主调用（ReAct）按 spec.tier 取模型（llm 显式注入时优先，
    测试行为不变）；extractor 摘要固定走 light tier。
    """
    _cache: dict = {}

    def _agent():
        if "agent" not in _cache:
            _cache["model"] = llm or get_llm(spec.tier)
            _cache["extractor_model"] = llm or get_llm("light")
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
        # C2 用户分析重点：启动参数 + USER.md 两来源合并注入（所有 Worker 统一入口）
        special = _load_user_special_requirements(
            project, state.get("user_focus"), state.get("user_exclude")
        )
        if special:
            task += (
                "\n\n【用户分析重点与排除约束（优先遵循）】\n" + special
            )
        # token 预算闸门：Worker ReAct 内层调用不经 invoke_guarded，统一在入口检查
        _enforce_token_budget(state)
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
                payload, artifact_type, f"{artifact_type}_summary", project,
                _cache["extractor_model"], config,
            )
        return {spec.output_key: payload}

    node.__name__ = spec.name
    return node


# === Phase -1: 预提取（纯函数节点）===

def _sync_user_priority_to_user_md(state: AnalysisState) -> None:
    """把启动参数的 focus/exclude（C2 用户分析优先级）落盘到 USER.md
    "用户着重关心的内容"段（user_md_set_focus 幂等追加，重跑不产生重复行）。

    落盘文本保留 focus/exclude 原文作为子串，供 _load_user_special_requirements
    做"启动参数 vs USER.md"两来源去重。仅在 fresh 分支调用（resume 时不覆盖
    用户在运行中途编辑过的 USER.md）。
    """
    project = state["sample_project_name"]
    focus = (state.get("user_focus") or "").strip()
    exclude = (state.get("user_exclude") or "").strip()
    if not focus and not exclude:
        return
    lines = []
    if focus:
        lines.append(f"- 重点关注（启动参数 --focus）：{focus}")
    if exclude:
        lines.append(
            f"- 排除领域（启动参数 --exclude）：{exclude}"
            "（用户指示不深入分析此部分的静态过程，只保留动调提取方案）"
        )
    user_md_set_focus(project, "\n".join(lines))


def pre_extract_node(state: AnalysisState) -> dict:
    """
    把 Phase -1 预提取结果写入黑板（resume 时跳过）。
    """
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
    # C2：启动参数 focus/exclude 落盘 USER.md（幂等，先落盘再跑预提取，
    # 保证后续任何节点读取 USER.md 都能拿到用户优先级）
    _sync_user_priority_to_user_md(state)
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
    """解析本样本激活了哪些知识指南。

    若传入 arch_detection 则直接使用（来自图状态中的 Phase 0 字符串分析）；
    否则从黑板上的 strings_summary 读取。将其与知识注册表匹配，并把结果持久化到
    meta/active_guides.json。永不抛异常：任何失败都回退到 windows_pe 基线。
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
    """依据 Phase 0 的 arch_detection 解析激活的知识指南。
    """
    string_analysis = state.get("string_analysis") or {}
    arch = string_analysis.get("arch_detection") if isinstance(string_analysis, dict) else None
    resolve_active_guides(state["sample_project_name"], arch_detection=arch)
    return {}


def _load_active_guides_text(project_name: str) -> str:
    """拼接所有激活指南的完整文本，用于注入 prompt。
    """

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


# === HITL 审批门（LangGraph interrupt() 挂起，由外层 CLI 恢复）===

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
    """根据图状态构建人类可读的审查消息。
    """
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
    """解析人工审查者回复的 CONFIRM 或 MODIFY。
    """
    text_stripped = text.strip()
    if text_stripped.upper() == "CONFIRM":
        return ("confirm", None)
    if text_stripped.upper().startswith("MODIFY "):
        addrs = [a.strip() for a in text_stripped[7:].split(",") if a.strip()]
        return ("modify", addrs)
    return ("invalid", None)


def approval_gate_node(state: AnalysisState) -> dict:
    """Phase 2→3 人工审批门（LangGraph interrupt()）。

    节点在 interrupt 处挂起（需要 checkpointer），外层运行器（main.py / 测试）
    从 interrupt 负载读取审查内容展示给人工，再以 Command(resume=回复) 恢复。
    无效回复会在节点内再次 interrupt（最多 3 次），之后默认 CONFIRM 放行。
    写入 state 的字段与语义同旧 CLI 版完全一致。
    """
    payload = {
        "kind": "phase2_approval",
        "message": build_review_message(state),
        "error": None,
    }
    max_attempts = 3
    for _attempt in range(max_attempts):
        reply = str(interrupt(payload)).strip()
        decision, addrs = parse_approval_reply(reply)
        if decision == "confirm":
            return {"phase2_human_decision": "CONFIRM"}
        if decision == "modify":
            return {
                "phase2_human_decision": reply,
                "human_approved_functions": addrs,
            }
        payload = {
            **payload,
            "error": f"无法识别回复: {reply}，请使用 CONFIRM 或 MODIFY 格式。",
        }
    return {"phase2_human_decision": "CONFIRM (default after max attempts)"}


# === Phase 3: 函数级深度分析（Send 并行扇出，Step 3 已落地）===

def _select_phase3_candidates(state: AnalysisState) -> list[dict]:
    """候选函数选取：人工 MODIFY 列表优先（无条件采纳，不受护栏影响）；
    否则对 LLM 候选施加代码级护栏（candidate_guards）：导出函数强制置顶 +
    疑似库函数排除，再按 analysis_priority>=7 补足 Top N。

    MODIFY 无条件采纳（A1 缺陷修复）：候选里已有的地址复用原条目（保留 LLM
    元数据），不在 LLM 候选中的地址合成最小条目补入——原实现直接按候选过滤，
    人工指定的圈外地址会被静默丢弃。

    护栏阈值取 config.yaml 的 analysis.*（环境变量兜底）：
    phase3_top_n / lib_xref_threshold / lib_tail_ratio / lib_size_max。
    """
    function_boundary = state.get("function_boundary_analysis") or {}
    all_candidates = function_boundary.get("candidates", [])

    human_addrs = state.get("human_approved_functions")
    if human_addrs:
        by_addr = {}
        for c in all_candidates:
            addr_n = normalize_addr(c.get("func_addr"))
            if addr_n and addr_n not in by_addr:
                by_addr[addr_n] = c
        picked = []
        for addr in human_addrs:
            addr_n = normalize_addr(addr)
            if not addr_n:
                continue
            existing = by_addr.get(addr_n)
            picked.append(existing if existing is not None else synthesized_human_candidate(addr_n))
        return picked

    project = state.get("sample_project_name", "")
    top_n = cfg_int("analysis.phase3_top_n", env="PHASE3_TOP_N", default=DEFAULT_TOP_N)
    xref_threshold = cfg_int(
        "analysis.lib_xref_threshold", env="LIB_XREF_THRESHOLD", default=DEFAULT_LIB_XREF_THRESHOLD
    )
    tail_ratio = float(
        cfg("analysis.lib_tail_ratio", env="LIB_TAIL_RATIO", default=DEFAULT_LIB_TAIL_RATIO)
    )
    size_max = cfg_int(
        "analysis.lib_size_max", env="LIB_SIZE_MAX", default=DEFAULT_LIB_SIZE_MAX
    )
    export_addrs = collect_export_addrs(state, project)
    # 尾部区间优先取黑板 functions_extract.json 的全量函数地址范围，
    # 读取失败时回退候选+导出地址集合估算
    addr_range = function_addr_range(
        project, [c.get("func_addr") for c in all_candidates] + list(export_addrs)
    )
    return apply_candidate_guards(
        all_candidates,
        export_addrs,
        top_n=top_n,
        xref_threshold=xref_threshold,
        tail_ratio=tail_ratio,
        size_max=size_max,
        addr_range=addr_range,
    )


# === Phase 3 双轨制（批次 A2）：主题任务 + 函数兜底任务的 manifest 构建与分波 ===

# 行为定型 → 默认主题映射：scheduler_decision.proposed_topics 为空时按
# behavior_profile.primary_type 兜底（Unknown/缺失 → 不提议主题）。
DEFAULT_TOPICS_BY_BEHAVIOR = {
    "RAT": ("command_dispatcher", "network_stack", "persistence"),
    "Stealer": ("stealer", "anti_analysis", "command_dispatcher"),
    "Loader": ("injection_loader", "init_config_decrypt", "anti_analysis"),
    "Backdoor": ("command_dispatcher", "persistence", "network_stack"),
}

# 主题间依赖（depends_on 的取值来源）：init_config_decrypt 产出的配置/密钥/C2 结论
# 是命令分发、网络回连、窃取目标解读的前置上下文，故这三个主题排在第二波执行。
# 只有依赖目标也出现在本次任务清单中时才真正落 depends_on（否则依赖悬空无意义）。
TOPIC_DEPENDS_ON = {
    "command_dispatcher": ("init_config_decrypt",),
    "network_stack": ("init_config_decrypt",),
    "stealer": ("init_config_decrypt",),
}

# 每个主题最多归组的函数数：主题节点一主题一次主调用，函数过多会撑爆 prompt。
TOPIC_MAX_FUNCS = 3


def _resolve_topics(state: AnalysisState) -> list[str]:
    """主题来源：scheduler_decision.proposed_topics 优先（去重保序，过滤词表外取值）；
    为空时按 behavior_profile.primary_type 查默认映射；Unknown/缺失返回空列表。
    """
    decision = state.get("scheduler_decision") or {}
    topics: list[str] = []
    for t in decision.get("proposed_topics") or []:
        if t in ANALYSIS_TOPIC_VOCABULARY and t not in topics:
            topics.append(t)
    if topics:
        return topics
    behavior = (state.get("behavior_profile") or {}).get("behavior_profile") or {}
    primary = behavior.get("primary_type", "Unknown")
    return list(DEFAULT_TOPICS_BY_BEHAVIOR.get(primary, ()))


def _pick_topic_functions(topic: str, pool: list[dict]) -> list[dict]:
    """主题归组启发式（确定性，无 LLM），从候选池中为本主题挑选函数。

    静态导出文本里没有调用图，无法精确知道"dispatcher 调用了哪些 handler"，
    只能用候选函数的元数据特征做近似，按主题特征强度分两类：

    强特征主题（有可靠的静态代理特征）：
    - command_dispatcher：is_export 候选优先（导出函数地址 ∩ LLM 候选 ≈ dispatcher
      入口），再按 xrefs 降序补足（向多 handler 扇出 ⇒ 高扇入是其静态近似）；
    - init_config_decrypt：按 size 降序（解密循环 + 初始化例程通常代码量最大）；
    - export_interface：全部 is_export 候选（导出函数即接口面）。

    弱特征主题（stealer / persistence / injection_loader / network_stack /
    anti_analysis）：静态文本无可靠函数级特征可辨，统一按 analysis_priority
    降序取头部候选，交给主题 Worker 做视角化解读。

    每主题上限 TOPIC_MAX_FUNCS；归组由调用方保证独占（一个函数只归一个主题）。
    """
    if not pool:
        return []
    if topic == "command_dispatcher":
        exports = [c for c in pool if c.get("is_export")]
        rest = sorted(
            (c for c in pool if not c.get("is_export")),
            key=lambda c: c.get("xrefs") or 0,
            reverse=True,
        )
        return (exports + rest)[:TOPIC_MAX_FUNCS]
    if topic == "init_config_decrypt":
        return sorted(pool, key=lambda c: c.get("size") or 0, reverse=True)[:TOPIC_MAX_FUNCS]
    if topic == "export_interface":
        return [c for c in pool if c.get("is_export")][:TOPIC_MAX_FUNCS]
    # 弱特征主题：优先级降序取头部
    return sorted(pool, key=lambda c: c.get("analysis_priority") or 0, reverse=True)[:TOPIC_MAX_FUNCS]


# 强特征主题先分、弱特征主题后分（避免高优先级候选被通用规则抢走，
# 导出/大体积这类强特征函数才能落到语义最贴切的主题上）
_STRONG_TOPICS = ("command_dispatcher", "init_config_decrypt", "export_interface")


def build_task_manifest(state: AnalysisState) -> TaskManifest:
    """构建 Phase 3 任务清单（主题任务 + 函数任务兜底 + 依赖分波标注）。

    流程：护栏修正后的候选函数（_select_phase3_candidates，含 MODIFY 无条件采纳）
    → 主题归组（两轮：强特征主题先分、弱特征主题后分，一个函数只归一个主题）
    → 未被任何主题覆盖的候选逐个生成函数兜底任务
    → 按 TOPIC_DEPENDS_ON 标注主题间依赖（仅当依赖目标也在本次清单中）。

    MODIFY 人工指定路径只产函数任务：人工已精确圈定分析范围，主题归组会稀释其意图。
    归组为空的主题不立项（主题节点只有函数上下文一个数据源，空归组必然
    insufficient_data，立项只会浪费一次 LLM 调用）。
    """
    candidates = _select_phase3_candidates(state)
    tasks: list[AnalysisTask] = []

    # MODIFY 路径：人工指定的函数列表逐个生成函数任务，无主题任务
    if state.get("human_approved_functions"):
        for c in candidates:
            addr = c.get("func_addr")
            if addr:
                tasks.append(AnalysisTask(
                    task_id=f"func_{addr}", kind="function", function_addrs=[addr],
                ))
        return TaskManifest(tasks=tasks)

    topics = _resolve_topics(state)
    assigned: dict[str, str] = {}  # 规范化地址 -> topic（独占分配）

    def _pool() -> list[dict]:
        return [
            c for c in candidates
            if normalize_addr(c.get("func_addr")) and normalize_addr(c.get("func_addr")) not in assigned
        ]

    # 两轮归组：强特征主题优先
    topic_funcs: dict[str, list[str]] = {}
    for round_topics in (
        [t for t in topics if t in _STRONG_TOPICS],
        [t for t in topics if t not in _STRONG_TOPICS],
    ):
        for topic in round_topics:
            picked = _pick_topic_functions(topic, _pool())
            if not picked:
                continue  # 空归组不立项
            addrs = [c.get("func_addr") for c in picked]
            topic_funcs[topic] = addrs
            for c in picked:
                assigned[normalize_addr(c.get("func_addr"))] = topic

    # 主题任务：依赖仅指向本次清单中真实存在的主题
    for topic, addrs in topic_funcs.items():
        deps = [
            f"topic_{dep}" for dep in TOPIC_DEPENDS_ON.get(topic, ())
            if dep in topic_funcs
        ]
        tasks.append(AnalysisTask(
            task_id=f"topic_{topic}", kind="topic", topic=topic,
            function_addrs=addrs, depends_on=deps,
        ))

    # 函数兜底：未被任何主题覆盖的护栏后候选
    for c in candidates:
        addr = c.get("func_addr")
        addr_n = normalize_addr(addr)
        if addr_n and addr_n not in assigned:
            tasks.append(AnalysisTask(
                task_id=f"func_{addr}", kind="function", function_addrs=[addr],
            ))
    return TaskManifest(tasks=tasks)


def _manifest_waves(state: AnalysisState) -> tuple[list[dict], list[dict]]:
    """把任务清单按 depends_on 分两波：wave0 = 无依赖任务（同波 Send 并行）；
    wave1 = 有依赖任务（等 wave0 全部完成后由 phase3_wave2 中继节点扇出）。

    优先读 state.task_manifest（dispatch 节点已写入）；缺失时回退现算
    （build_task_manifest 是幂等纯函数，直调 fanout 的测试也走这条路）。
    """
    manifest = state.get("task_manifest")
    if not manifest:
        manifest = build_task_manifest(state).model_dump()
    tasks = manifest.get("tasks") or []
    wave0 = [t for t in tasks if not t.get("depends_on")]
    wave1 = [t for t in tasks if t.get("depends_on")]
    return wave0, wave1


def _phase3_candidate_map(state: AnalysisState) -> dict:
    """护栏后候选的规范化地址 → 候选条目映射（函数任务 Send 载荷恢复元数据用）。"""
    result = {}
    for c in _select_phase3_candidates(state):
        addr_n = normalize_addr(c.get("func_addr"))
        if addr_n:
            result[addr_n] = c
    return result


def _task_base_payload(state: AnalysisState) -> dict:
    return {
        "sample_project_name": state["sample_project_name"],
        "sample_export_dir": state["sample_export_dir"],
        # C2：Send 扇出的是部分状态，user_focus/user_exclude 必须显式透传，
        # 否则主题/函数节点读不到用户分析重点（缺省为 None，节点侧容错）
        "user_focus": state.get("user_focus"),
        "user_exclude": state.get("user_exclude"),
    }


def _topic_send(task: dict, state: AnalysisState, node: str) -> Send:
    """主题任务 Send：载荷即主题节点输入（analysis_task 为 AnalysisTask dict）。"""
    return Send(node, {**_task_base_payload(state), "analysis_task": task})


def _function_send(task: dict, state: AnalysisState, cand_map: dict) -> Send:
    """函数任务 Send：从护栏后候选映射恢复 phase3_candidate 元数据；
    映射缺失时合成最小条目（防御性兜底，正常不会发生）。"""
    addr = (task.get("function_addrs") or [""])[0]
    addr_n = normalize_addr(addr)
    candidate = cand_map.get(addr_n) or synthesized_human_candidate(addr_n or str(addr))
    return Send(
        "phase3_function",
        {**_task_base_payload(state), "phase3_candidate": candidate},
    )


def phase3_dispatch_node(state: AnalysisState) -> dict:
    """Phase 3 调度节点：构建 TaskManifest 落盘 meta/task_manifest.json 并写入 state，
    记录扇出日志；真正的扇出由条件边 phase3_fanout / phase3_fanout_wave2 完成。
    """
    project = state["sample_project_name"]
    manifest = build_task_manifest(state)
    manifest_dict = manifest.model_dump()

    meta_dir = board_path(project, "meta")
    os.makedirs(meta_dir, exist_ok=True)
    with open(os.path.join(meta_dir, "task_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest_dict, f, ensure_ascii=False, indent=2)

    wave0, wave1 = _manifest_waves({**state, "task_manifest": manifest_dict})
    if not manifest.tasks:
        bb_log_event("phase3_skipped", {"reason": "no_candidates"}, project)
    else:
        bb_log_event(
            "phase3_dispatch",
            {
                "task_count": len(manifest.tasks),
                "topic_tasks": [t.topic for t in manifest.tasks if t.kind == "topic"],
                "function_tasks": [
                    t.function_addrs[0] for t in manifest.tasks
                    if t.kind == "function" and t.function_addrs
                ],
                "wave0_count": len(wave0),
                "wave1_count": len(wave1),
            },
            project,
        )
    # 两个 refs 键始终落 state：reducer add 语义下空列表不改变后续聚合，
    # 但能保证下游/终态读取时键存在（空任务直通 verification 的场景）
    return {
        "task_manifest": manifest_dict,
        "func_analysis_refs": [],
        "topic_analysis_refs": [],
    }


def phase3_fanout(state: AnalysisState):
    """条件边（第一波）：wave0 任务逐个 Send 扇出（无依赖主题 → phase3_topic，
    函数兜底 → phase3_function）。

    wave0 空但 wave1 非空时直通 phase3_wave2 中继节点；全空直通 orchestrator
    （质量编排节点，再由它进入 verification_agent——验证不只覆盖 Phase 3：
    Phase 0-2 的 high 置信度发现同样需要回查）。
    """
    wave0, wave1 = _manifest_waves(state)
    if not wave0:
        return "phase3_wave2" if wave1 else "orchestrator"
    sends: list = []
    cand_map: Optional[dict] = None
    for task in wave0:
        if task.get("kind") == "topic":
            sends.append(_topic_send(task, state, "phase3_topic"))
        else:
            if cand_map is None:
                cand_map = _phase3_candidate_map(state)
            sends.append(_function_send(task, state, cand_map))
    return sends


def phase3_wave2_node(state: AnalysisState) -> dict:
    """Phase 3 第二波中继节点：wave0（无依赖主题 + 函数兜底）全部完成后经扇入触发，
    节点本身只记录日志，wave1 扇出由条件边 phase3_fanout_wave2 完成。
    """
    project = state["sample_project_name"]
    _wave0, wave1 = _manifest_waves(state)
    bb_log_event(
        "phase3_wave2",
        {"wave1_topics": [t.get("topic") for t in wave1]},
        project,
    )
    return {}


def phase3_fanout_wave2(state: AnalysisState):
    """条件边（第二波）：wave1 有依赖主题任务扇出到 phase3_topic_dep；
    空时直通 orchestrator（质量编排节点，再进入 verification_agent）。
    """
    _wave0, wave1 = _manifest_waves(state)
    if not wave1:
        return "orchestrator"
    return [_topic_send(task, state, "phase3_topic_dep") for task in wave1]


def make_phase3_function_node(llm=None, tier: str = "strong"):
    """构建 Phase 3 单函数深度分析节点（经 Send 扇出并行执行）。

    并发上限由 analysis.phase3_max_concurrency（默认 4，环境变量 PHASE3_MAX_CONCURRENCY
    兜底）控制：同一图内的并行任务共享同一事件循环，节点内 asyncio.Semaphore 限制
    同时进行的 LLM 调用数，防止 API 限流。黑板写入均为同步调用，在事件循环内天然
    串行执行，不存在文件写竞争。

    模型分层：主调用按 tier（默认 strong）；extractor 摘要固定走 light tier；
    llm 显式注入时两者都用注入模型（测试行为不变）。
    """
    max_concurrency = cfg_int(
        "analysis.phase3_max_concurrency", env="PHASE3_MAX_CONCURRENCY", default=4
    )
    semaphore = asyncio.Semaphore(max_concurrency)

    async def phase3_function_node(state: dict, config: RunnableConfig = None) -> dict:
        model = llm or get_llm(tier)
        extractor_model = llm or get_llm("light")
        project = state["sample_project_name"]
        candidate = state.get("phase3_candidate") or {}
        addr = candidate.get("func_addr")
        name = candidate.get("func_name", f"func_{addr}")

        # 幂等：重跑跳过已完成的函数（不调 LLM，直接返回引用）
        if bb_has_artifact(f"phase3_func_{addr}", project):
            return {"func_analysis_refs": [{"addr": addr, "skipped": True}]}

        func_data = load_function_data(addr, state["sample_export_dir"])
        if func_data.get("status") != "success":
            return {"func_analysis_refs": [{"addr": addr, "status": "load_failed"}]}

        guides_text = _load_active_guides_text(project)
        prompt = build_func_analysis_prompt(
            addr, name, func_data,
            guides=guides_text,
            project_name=project,
            # C2 用户分析重点与排除约束（启动参数 + USER.md 合并去重）
            special_requirements=_load_user_special_requirements(
                project, state.get("user_focus"), state.get("user_exclude")
            ),
        )
        async with semaphore:
            resp = await invoke_guarded(model, [("user", prompt)], config=config, project_name=project)
            artifact = parse_json_loose(getattr(resp, "content", resp))
            bb_write_artifact(f"phase3_func_{addr}", artifact, project)

            summary = await run_extraction(
                artifact, "function_deep", f"phase3_funcs/func_{addr}", project, extractor_model, config
            )
        bb_checkpoint(f"phase3_progress_{addr}", project)
        return {"func_analysis_refs": [{"addr": addr, "summary": summary}]}

    return phase3_function_node


def build_user_priority_text(focus: str = "", exclude: str = "") -> str:
    """把启动参数的 focus/exclude 渲染为统一的"用户分析重点"prompt 文本（C2）。

    行为约束对齐金标准：focus 领域优先详写；exclude 领域不深入静态过程、
    不阻塞整体流程、产物中标注边界，结果性数据只给动态调试提取方案。
    两者都为空时返回空字符串（缺省零行为变化）。
    """
    focus = (focus or "").strip()
    exclude = (exclude or "").strip()
    parts = []
    if focus:
        parts.append(
            "【用户分析重点（启动参数 --focus）】\n"
            f"用户明确重点关注以下领域：{focus}\n"
            "要求：涉及这些领域的分析维度、主题结论与报告章节优先详细展开，"
            "逐条给出机制还原与逐字证据引用。"
        )
    if exclude:
        parts.append(
            "【用户排除领域（启动参数 --exclude）】\n"
            f"用户指示不深入分析此部分：{exclude}\n"
            "约束（严格遵守）：\n"
            "1. 不展开这些领域的静态实现细节分析；不阻塞整体分析流程——"
            "这些领域信息缺失时如实标注缺口即可；\n"
            "2. 产物中涉及这些领域的位置统一标注\"用户指示不深入分析此部分\"，说明分析边界；\n"
            "3. 这些领域所需的结果性数据（如密钥、配置明文、解密后的载荷），只提供动态调试"
            "提取方案（断点位置、观察方法、预期可获得的数据），不展开静态分析过程。"
        )
    return "\n\n".join(parts)


def _load_user_special_requirements(
    project_name: str,
    focus: Optional[str] = None,
    exclude: Optional[str] = None,
) -> str:
    """汇总"用户特殊要求"文本，供各 prompt 注入点统一使用。

    两个来源合一（C2）：
    1. USER.md（异步人机沟通文档）的"用户着重关心的内容"段与已回答问题——
       用户在图运行中途经 Web UI / 手工写入的回答，从下一次主题分析开始生效；
    2. 启动参数 focus/exclude（state 的 user_focus / user_exclude，由调用方传入）——
       经 build_user_priority_text 渲染为统一的重点/排除约束文本。

    去重：pre_extract 已把启动参数落盘进 USER.md focus 段（保留原文子串），
    因此 USER.md 段已包含启动参数原文时不再追加启动参数段，避免重复注入。
    文件不存在时 user_md_read 自动建骨架并返回空内容。
    """
    parts = []
    md_focus = ""
    result = user_md_read(project_name)
    if result.get("status") == "success":
        md_focus = (result.get("focus") or "").strip()
        if md_focus:
            parts.append(f"【用户着重关心的内容（USER.md）】\n{md_focus}")
        for q in result.get("questions", []):
            if not q.get("answered"):
                continue
            parts.append(
                f"【问题 {q['no']}】{q['title']}\n"
                f"Agent 提问：{q['body']}\n"
                f"用户回答：{q['answer']}"
            )

    # 启动参数来源：分别判断 focus / exclude 原文是否已被 USER.md 覆盖（落盘去重）
    need_focus = bool((focus or "").strip()) and (focus or "").strip() not in md_focus
    need_exclude = bool((exclude or "").strip()) and (exclude or "").strip() not in md_focus
    if need_focus or need_exclude:
        cli_text = build_user_priority_text(
            focus if need_focus else "", exclude if need_exclude else ""
        )
        if cli_text:
            parts.append(cli_text)
    return "\n\n".join(parts)


def make_topic_node(llm=None, tier: str = "strong"):
    """构建 Phase 3 主题分析节点（经 Send 扇出；一主题一次主调用，不做 ReAct 循环）。

    成本控制：函数上下文由节点内 load_function_data 聚好后直接注入 prompt，
    全程只有"主题主调用 + extractor 摘要"两次 LLM 调用，不走 create_agent。

    并发上限同样取 analysis.phase3_max_concurrency，但信号量与函数轨各自独立：
    主题任务数量少（主题词表 8 个，实际每轮 2-4 个），且与函数任务只在 wave0
    同波重叠，独立计数的最坏峰值（2×上限）在可接受范围，换来两个工厂零耦合。

    幂等：bb_has_artifact("topic_{topic}") 命中即跳过，不调 LLM。

    模型分层：主调用按 tier（默认 strong）；extractor 摘要固定走 light tier；
    llm 显式注入时两者都用注入模型（测试行为不变）。
    """
    max_concurrency = cfg_int(
        "analysis.phase3_max_concurrency", env="PHASE3_MAX_CONCURRENCY", default=4
    )
    semaphore = asyncio.Semaphore(max_concurrency)

    async def phase3_topic_node(state: dict, config: RunnableConfig = None) -> dict:
        model = llm or get_llm(tier)
        extractor_model = llm or get_llm("light")
        project = state["sample_project_name"]
        task = state.get("analysis_task") or {}
        topic = task.get("topic") or "unknown"
        task_id = task.get("task_id") or f"topic_{topic}"
        function_addrs = task.get("function_addrs") or []

        # 幂等：重跑跳过已完成主题（不调 LLM，直接返回引用）
        if bb_has_artifact(f"topic_{topic}", project):
            return {"topic_analysis_refs": [{"topic": topic, "task_id": task_id, "skipped": True}]}

        # 聚合上下文：对任务函数地址集合逐个加载反编译/反汇编片段（复用现有工具）
        func_contexts = [
            load_function_data(addr, state["sample_export_dir"]) for addr in function_addrs
        ]

        # 依赖前置主题结论：读 depends_on 主题的 extractor 摘要（第二波任务的数据流输入）
        prerequisites = {}
        for dep_id in task.get("depends_on") or []:
            dep_topic = dep_id[len("topic_"):] if dep_id.startswith("topic_") else dep_id
            result = bb_read_summary(f"topics/{dep_topic}", project)
            if result.get("status") == "success":
                prerequisites[dep_topic] = result.get("data") or {}

        prompt = build_topic_prompt(
            topic,
            function_addrs,
            func_contexts,
            guides=_load_active_guides_text(project),
            project_name=project,
            prerequisites=prerequisites,
            # USER.md 异步通道 + C2 启动参数：每波任务开始前读取用户已回答内容与
            # focus/exclude（state 的 user_focus/user_exclude），合并去重后注入"特殊要求"段
            special_requirements=_load_user_special_requirements(
                project, state.get("user_focus"), state.get("user_exclude")
            ),
        )
        async with semaphore:
            resp = await invoke_guarded(model, [("user", prompt)], config=config, project_name=project)
            artifact = parse_json_loose(getattr(resp, "content", resp))
            artifact.setdefault("topic", topic)
            artifact.setdefault("status", "success")
            bb_write_artifact(f"topic_{topic}", artifact, project)

            summary = await run_extraction(
                artifact, "topic", f"topics/{topic}", project, extractor_model, config
            )
        bb_checkpoint(f"phase3_topic_{topic}", project)
        return {"topic_analysis_refs": [
            {"topic": topic, "task_id": task_id, "summary": summary}
        ]}

    return phase3_topic_node


# === Phase 3 后置：orchestrator 质量编排节点（纯代码，不调 LLM）===
#
# 对齐金标准工作流的父 Agent 职责（一切交流落盘归档）：
# 产物归档（AGENT_XX 五要素）+ 质量检查 + 缺口识别 + 矛盾发现（→ USER.md）。
# 图位置：phase3_wave2 / phase3_topic_dep 之后、verification_agent 之前
# （两波 Phase 3 全部完成后统一执行一次）。

def _quality_missing_fields(payload: dict, kind: str) -> list:
    """五要素质量检查：返回产物缺失的关键字段列表（空列表 = 通过）。

    规则（保守，只标记不重试——重试留给后续批次）：
    - status=insufficient_data 是合法结论（数据不足），豁免检查；
    - 分析结论缺失：summary / functionality / overall_assessment 全空；
    - 主题产物：findings / evidence 任一为空；
    - 函数产物没有 findings/evidence 字段，其"关键引用"对应
      suspicious_behaviors / key_apis / evidence，三者全空算缺失。
    """
    if payload.get("status") == "insufficient_data":
        return []
    missing = []
    if not (
        payload.get("summary")
        or payload.get("functionality")
        or payload.get("overall_assessment")
    ):
        missing.append("conclusion")
    if kind == "topic":
        if not payload.get("findings"):
            missing.append("findings")
        if not payload.get("evidence"):
            missing.append("evidence")
    else:
        if not (
            payload.get("evidence")
            or payload.get("suspicious_behaviors")
            or payload.get("key_apis")
        ):
            missing.append("evidence")
    return missing


# 矛盾发现启发式用的功能判定关键词表（保守：只覆盖最常见、歧义少的类别）。
# 同一函数地址在两个主题产物中被判成不相交的类别集时才报疑似矛盾——
# 静态导出文本里没有调用图，这只是"值得人工看一眼"的提示，不是自动裁决。
_CONTRADICTION_KEYWORDS = {
    "解密": ("解密", "decrypt", "xor", "rc4", "aes", "des"),
    "网络": ("网络", "c2", "http", "socket", "回连", "下载"),
    "窃取": ("窃取", "steal", "凭据", "cookie", "密码"),
    "持久化": ("持久化", "驻留", "run 键", "计划任务", "服务"),
    "注入": ("注入", "inject", "shellcode", "镂空"),
    "反分析": ("反调试", "反虚拟", "反沙箱", "anti-", "混淆"),
}
_ORCH_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")


def _topic_payload_categories(payload: dict) -> set:
    """从主题产物的结论文本（summary + 各 finding.conclusion）提取功能类别集合。"""
    texts = [str(payload.get("summary") or "")]
    for f in payload.get("findings") or []:
        if isinstance(f, dict):
            texts.append(str(f.get("conclusion") or ""))
    blob = "\n".join(texts).lower()
    return {
        cat for cat, kws in _CONTRADICTION_KEYWORDS.items()
        if any(kw in blob for kw in kws)
    }


def _topic_payload_addrs(payload: dict) -> set:
    """主题产物涉及的函数地址集合（evidence.address 与 findings.subject 中的 0x 地址）。"""
    addrs = set()
    for ev in payload.get("evidence") or []:
        if isinstance(ev, dict):
            addrs.update(a.lower() for a in _ORCH_ADDR_RE.findall(str(ev.get("address") or "")))
    for f in payload.get("findings") or []:
        if isinstance(f, dict):
            addrs.update(a.lower() for a in _ORCH_ADDR_RE.findall(str(f.get("subject") or "")))
    return addrs


def _detect_topic_contradictions(topic_payloads: dict) -> list:
    """矛盾发现（启发式）：两主题对同一函数地址的功能判定关键词冲突。

    保守规则：地址同时出现在两个主题产物中，且两者各自提取的功能类别集合
    都非空且互不相交，才记一条疑似矛盾，交由 USER.md 请用户确认（不自动裁决）。
    主题归组本身保证一个函数只归一个主题，但 evidence/subject 可能跨主题引用
    同一地址（典型如 dispatcher 与其 handler），正是需要人工复核的解读冲突。
    """
    topics = sorted(topic_payloads)
    contradictions = []
    for i in range(len(topics)):
        for j in range(i + 1, len(topics)):
            topic_a, topic_b = topics[i], topics[j]
            shared = (
                _topic_payload_addrs(topic_payloads[topic_a])
                & _topic_payload_addrs(topic_payloads[topic_b])
            )
            if not shared:
                continue
            cats_a = _topic_payload_categories(topic_payloads[topic_a])
            cats_b = _topic_payload_categories(topic_payloads[topic_b])
            if not cats_a or not cats_b or cats_a & cats_b:
                continue
            for addr in sorted(shared):
                contradictions.append({
                    "address": addr,
                    "topic_a": topic_a,
                    "topic_b": topic_b,
                    "categories_a": sorted(cats_a),
                    "categories_b": sorted(cats_b),
                })
    return contradictions


def _task_artifact_name(task: dict) -> tuple:
    """任务 → (归档对象名, artifact 名)：主题轨 topic_{topic}，函数轨 phase3_func_{addr}。"""
    kind = task.get("kind") or "function"
    if kind == "topic":
        subject = task.get("topic") or "unknown"
        return subject, f"topic_{subject}"
    addr = (task.get("function_addrs") or [""])[0]
    return f"func_{addr}", f"phase3_func_{addr}"


def orchestrator_node(state: AnalysisState) -> dict:
    """Phase 3 后置质量编排节点（纯代码，不调 LLM）。

    1. 把 wave0+wave1 的主题/函数产物渲染归档为 docs/{project}/AGENT_XX_{主题}.md
       （幂等：同对象已归档则跳过，序号从已有最大值续排）；
    2. 五要素质量检查：产物缺关键字段 → 标记 quality_failed 并记日志（不重试）；
    3. 缺口识别：manifest 任务 vs 实际 artifact，未完成的记入 meta/gap_report.json；
    4. 矛盾发现（启发式）：两主题对同一函数的功能判定关键词冲突 → USER.md 待确认
       问题（同标题去重）；
    5. state 写入 orchestrator_report（质量/缺口/矛盾计数）。
    """
    project = state["sample_project_name"]
    manifest = state.get("task_manifest") or {}
    if not manifest:
        # state 缺失时回退读盘（dispatch 已落盘 meta/task_manifest.json）
        manifest_path = board_path(project, "meta", "task_manifest.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
            except Exception:
                manifest = {}
    tasks = manifest.get("tasks") or []

    # 幂等基线：已归档的同主题/函数不再重写，序号续排
    existing = docs_read_agent_reports(project)
    archived_subjects = {r["topic"] for r in existing.get("reports", [])}
    seq = max((r["seq"] for r in existing.get("reports", [])), default=0) + 1

    docs_written = 0
    quality_failed: list = []
    topic_payloads: dict = {}

    for task in tasks:
        subject, artifact_name = _task_artifact_name(task)
        result = bb_read_artifact(artifact_name, project)
        if result.get("status") != "success":
            continue  # 缺口统一在下方统计
        payload = result.get("data") or {}
        if (task.get("kind") or "function") == "topic":
            topic_payloads[subject] = payload
        missing = _quality_missing_fields(payload, task.get("kind") or "function")
        if missing:
            quality_failed.append({"task_id": task.get("task_id"), "missing": missing})
            bb_log_event(
                "orchestrator_quality_failed",
                {"task_id": task.get("task_id"), "missing": missing},
                project,
            )
        if subject in archived_subjects:
            continue
        written = docs_write_agent_report(project, seq, subject, payload)
        if written.get("status") == "success":
            docs_written += 1
            seq += 1

    # 缺口识别：manifest 任务 vs 实际 artifact（缺失即未完成）
    gaps = []
    for task in tasks:
        _subject, artifact_name = _task_artifact_name(task)
        if not bb_has_artifact(artifact_name, project):
            gaps.append({
                "task_id": task.get("task_id"),
                "kind": task.get("kind") or "function",
                "artifact": artifact_name,
                "reason": "artifact_missing",
            })
    gap_report = {
        "status": "success",
        "generated_at": _now_iso(),
        "project": project,
        "total_tasks": len(tasks),
        "gaps": gaps,
    }
    meta_dir = board_path(project, "meta")
    os.makedirs(meta_dir, exist_ok=True)
    with open(os.path.join(meta_dir, "gap_report.json"), "w", encoding="utf-8") as f:
        json.dump(gap_report, f, ensure_ascii=False, indent=2)

    # 矛盾发现（启发式）→ USER.md 待确认问题（同标题去重，保证节点幂等）
    contradictions = _detect_topic_contradictions(topic_payloads)
    existing_titles = set()
    if contradictions:
        read = user_md_read(project)
        if read.get("status") == "success":
            existing_titles = {q["title"] for q in read.get("questions", [])}
    for c in contradictions:
        title = f"矛盾确认：{c['address']} 在 {c['topic_a']}/{c['topic_b']} 的功能判定冲突"
        if title in existing_titles:
            continue
        body = (
            f"启发式检查发现：函数 {c['address']} 同时出现在两个主题的产物中，"
            "但功能判定类别不相交（静态文本关键词启发式，仅供人工复核）。\n\n"
            f"- 主题 {c['topic_a']}：判定类别 {('、'.join(c['categories_a']))}\n"
            f"- 主题 {c['topic_b']}：判定类别 {('、'.join(c['categories_b']))}\n\n"
            "请确认该函数的真实功能归属，或说明两个主题各自的解读边界。"
        )
        user_md_append_question(project, title, body)

    report = {
        "status": "success",
        "project": project,
        "generated_at": _now_iso(),
        "docs_written": docs_written,
        "quality_failed": quality_failed,
        "gaps": gaps,
        "contradictions": contradictions,
        "counts": {
            "docs_written": docs_written,
            "quality_failed": len(quality_failed),
            "gaps": len(gaps),
            "contradictions": len(contradictions),
        },
    }
    bb_log_event("orchestrator_report", report["counts"], project)
    bb_checkpoint("orchestrator_complete", project)
    return {"orchestrator_report": report}


# === Phase 4: 综合报告（Map-Reduce，分片串行为小模型稳定性保留）===

def _read_phase01_summaries(project_name: str) -> dict:
    """从黑板读取 Phase 0/1 的五份 summary。
    """
    return {
        "p0_strings": bb_read_summary("strings_summary", project_name),
        "p0_api": bb_read_summary("api_summary", project_name),
        "p0_exports": bb_read_summary("exports_summary", project_name),
        "p1_behavior": bb_read_summary("behavior_summary", project_name),
        "p1_functions": bb_read_summary("functions_summary", project_name),
    }


def _summary_data(summary: dict) -> dict:
    return summary.get("data") if summary.get("status") == "success" else {}


def _read_topic_summaries(project_name: str) -> list[dict]:
    """读取 Phase 3 主题轨的全部摘要（summary/topics/{topic}.json），无主题时为空列表。

    供 Phase 4 三个节点消费：shard 用来印证函数级发现，aggregator 提炼
    topic_conclusions，report_generator 填充能力矩阵/C2 提取等章节。
    """
    return bb_list_summaries("topics/", project_name)


def _read_preclassified_iocs(project_name: str, max_items_per_cat: int = 10) -> dict:
    """读取 Phase -1 的确定性规则分类产物（零 token），裁剪后供报告章节直接引用。

    strings_categorized / imports_categorized 明细可能很大（全样本字符串），
    每类只保留前 max_items_per_cat 条明细并附计数；产物缺失（旧黑板数据）时对应键缺席。
    """
    out: dict = {}
    strings = bb_read_extract("strings_categorized", project_name)
    if strings.get("status") == "success":
        data = strings["data"]
        cats = data.get("categories", {})
        out["strings"] = {
            "total_count": data.get("total_count", 0),
            "category_counts": data.get("category_counts", {}),
            "top_items": {
                cat: [item.get("text", "") for item in c.get("items", [])[:max_items_per_cat]]
                for cat, c in cats.items()
            },
            "note": f"每类仅列前 {max_items_per_cat} 条，全量见 extracts/strings_categorized.json",
        }
    imports = bb_read_extract("imports_categorized", project_name)
    if imports.get("status") == "success":
        data = imports["data"]
        cats = data.get("categories", {})
        out["imports"] = {
            "total_count": data.get("total_count", 0),
            "category_counts": data.get("category_counts", {}),
            "top_items": {
                cat: [
                    (f"{item.get('dll')}!{item.get('api')}" if item.get("dll")
                     else item.get("raw") or item.get("api", ""))
                    for item in c.get("items", [])[:max_items_per_cat]
                ]
                for cat, c in cats.items()
            },
            "note": f"每类仅列前 {max_items_per_cat} 条，全量见 extracts/imports_categorized.json",
        }
    return out


def _collect_decompile_failed_functions(project_name: str, max_items: int = 50) -> list[str]:
    """从 functions_extract.json 全量扫描反编译失败（disassembly-fallback）的函数地址。

    不走 bb_read_extract（它对 functions_extract 有 100 条/片的分片逻辑），直接读全量
    JSON 后过滤；文件缺失/解析失败时返回空列表（旧黑板数据兼容）。
    """
    path = board_path(project_name, "extracts", "functions_extract.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    addrs = [
        fn["address"]
        for fn in data.get("functions", [])
        if fn.get("type") == "disassembly-fallback" and fn.get("address")
    ]
    return addrs[:max_items]


# 全局变量候选扫描：g_ 前缀标识符（对齐金标准手册第 6 章的命名习惯）
_GVAR_CANDIDATE_RE = re.compile(r"\bg_[A-Za-z0-9_]+\b")


def _collect_global_var_candidates(project_name: str, max_items: int = 50) -> list[dict]:
    """从主题/函数产物的文本中机器预扫描 g_ 前缀全局变量候选（确定性、零 token）。

    扫描范围：主题轨完整 artifact（topic_*，含 evidence 原文）+ 函数轨摘要
    （phase3_funcs/）。按变量名去重并记录首个来源；扫描不到时返回空列表，
    报告章节据此标注"未发现"而非编造。
    """
    candidates: dict[str, str] = {}  # name -> 首个来源

    def _scan(payload, source: str) -> None:
        for name in _GVAR_CANDIDATE_RE.findall(json.dumps(payload, ensure_ascii=False)):
            candidates.setdefault(name, source)

    listed = bb_list_artifacts("topic_", project_name)
    if listed.get("status") == "success":
        for artifact_name in listed.get("artifacts", []):
            artifact = bb_read_artifact(artifact_name, project_name)
            if artifact.get("status") == "success":
                _scan(artifact.get("data"), artifact_name)
    for summary in bb_list_summaries("phase3_funcs/", project_name):
        _scan(summary, "phase3_funcs")

    return [
        {"name": name, "source": source}
        for name, source in sorted(candidates.items())
    ][:max_items]


def make_shard_synthesis_node(llm=None, tier: str = "strong"):
    """构建 Phase 4 的 map 节点：对可疑函数做分片综合。

    输入除 Phase 0/1 摘要与函数轨摘要外，还包含主题轨摘要（summary/topics/，
    A2 遗留修复），供 shard 印证/补充函数级发现。
    """

    async def shard_synthesis_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm(tier)
        project = state["sample_project_name"]
        s = _read_phase01_summaries(project)
        p3_summaries = bb_list_summaries("phase3_funcs/", project)
        # A2 遗留修复：主题轨摘要（summary/topics/）纳入分片上下文，
        # 供 shard 印证/补充函数级发现（不超出主题摘要内容）
        topic_summaries = _read_topic_summaries(project)

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
                "topic_summaries": topic_summaries,
                "shard_id": idx + 1,
            }
            resp = await invoke_guarded(
                model,
                [
                    ("system", SHARD_SYNTHESIS_PROMPT),
                    ("user", json.dumps(shard_context, ensure_ascii=False)),
                ],
                config=config,
                project_name=project,
            )
            report = parse_json_loose(getattr(resp, "content", resp))
            if report.get("parse_error"):
                report["shard_id"] = idx + 1
                report["status"] = "parse_failed"
            shard_reports.append(report)

        return {"shard_reports": shard_reports}

    return shard_synthesis_node


def make_aggregator_node(llm=None, tier: str = "strong"):
    """构建 Phase 4 的 reduce 节点：把各分片报告聚合为最终报告。

    输入含主题轨摘要（A2 遗留修复），输出 p4_final_report 新增 topic_conclusions
    主题结论要点（提炼 ≤10 条，仍受 summary ≤1500 tokens 硬限制）。
    """

    async def aggregator_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm(tier)
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
            # A2 遗留修复：主题轨摘要纳入聚合，提炼为 topic_conclusions 进 p4_final_report
            "topic_summaries": _read_topic_summaries(project),
        }
        resp = await invoke_guarded(
            model,
            [
                ("system", AGGREGATOR_PROMPT),
                ("user", json.dumps(aggregate_context, ensure_ascii=False)),
            ],
            config=config,
            project_name=project,
        )
        report = parse_json_loose(getattr(resp, "content", resp))
        bb_write_summary("p4_final_report", report, project)
        bb_checkpoint("phase4_complete", project)
        return {"final_report_ref": "bb://summary/p4_final_report"}

    return aggregator_node


# === Phase 4 收尾：综合参考手册（Markdown 落盘，不走 summary 1500 tokens 限制）===

REPORT_MD_FILENAME = "final_report.md"


def _strip_markdown_fence(text: str) -> str:
    """去掉模型输出可能给整篇文档附带的 markdown 代码围栏。"""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = [l for l in lines if not l.strip().startswith("```")]
        stripped = "\n".join(lines).strip()
    return stripped


def make_report_generator_node(llm=None, tier: str = "strong"):
    """构建综合报告节点：汇总全部产出，生成面向动态调试的 Markdown 参考手册。

    手册正文直接写 data/output/{project}/final_report.md（不受 summary 1500 tokens
    硬限制）；另以 bb_write_artifact 存一份 JSON 元数据（路径/来源引用/生成时间）。
    """

def make_report_generator_node(llm=None, tier: str = "strong"):
    """构建综合报告节点：汇总全部产出，生成面向动态调试的 9 章 Markdown 参考手册。

    手册正文直接写 data/output/{project}/final_report.md（不受 summary 1500 tokens
    硬限制）；另以 bb_write_artifact 存一份 JSON 元数据（路径/来源引用/生成时间）。

    输入收集（9 章数据源）：Phase 0/1 摘要 + behavior_profile（state 优先，含
    breakpoint_matrix 断点矩阵）+ 主题轨摘要（summary/topics/，A2 遗留修复）+
    orchestrator_report + Phase -1 确定性分类产物（preclassified_iocs，截断）+
    反编译失败函数列表 + g_ 全局变量机器预扫描候选 + USER.md 用户特殊要求。
    """

    async def report_generator_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm(tier)
        project = state["sample_project_name"]
        s = _read_phase01_summaries(project)

        # 优先用图状态中的验证报告（完整分桶），缺席时回退黑板上的验证摘要
        verification = state.get("verification_report")
        if not verification:
            verification = _summary_data(bb_read_summary("verification_summary", project))

        # behavior_profile 优先取图状态原文（含完整 breakpoint_matrix P0/P1/P2 结构），
        # 缺席（如旧黑板续跑）时回退 extractor 摘要（其 schema 同样含 breakpoint_matrix）
        behavior_profile = state.get("behavior_profile") or _summary_data(s["p1_behavior"])

        report_context = {
            "project_name": project,
            "phase0_summary": {
                "strings": _summary_data(s["p0_strings"]),
                "api": _summary_data(s["p0_api"]),
                "exports": _summary_data(s["p0_exports"]),
            },
            "phase1_summary": {
                "behavior": _summary_data(s["p1_behavior"]),
                "functions": _summary_data(s["p1_functions"]),
            },
            "behavior_profile": behavior_profile,
            # A2 遗留修复：主题轨摘要进入最终手册（能力矩阵/C2 提取/调试注意等章节）
            "topic_summaries": _read_topic_summaries(project),
            "phase3_function_summaries": bb_list_summaries("phase3_funcs/", project),
            "orchestrator_report": state.get("orchestrator_report") or {},
            "shard_reports": state.get("shard_reports", []),
            "verification_report": verification or {},
            "final_report": _summary_data(bb_read_summary("p4_final_report", project)),
            # Phase -1 确定性规则分类产物（零模型推断，每类截断前若干条）
            "preclassified_iocs": _read_preclassified_iocs(project),
            # 反编译失败函数（只有反汇编）：第 7 章提取方案以断点+内存观察为主
            "decompile_failed_functions": _collect_decompile_failed_functions(project),
            # g_ 前缀全局变量机器预扫描候选（空列表=未发现，报告据此标注而非编造）
            "global_var_candidates": _collect_global_var_candidates(project),
        }
        user_content = json.dumps(report_context, ensure_ascii=False)
        # USER.md 异步通道 + C2 启动参数（合并去重）：focus/已回答问题拼接进 prompt，
        # 影响章节详略（exclude 维度只给动调提取方案，不展开静态过程）
        special = _load_user_special_requirements(
            project, state.get("user_focus"), state.get("user_exclude")
        )
        if special:
            user_content += (
                "\n\n【用户特殊要求（启动参数与 USER.md，影响章节详略，优先级高于默认填充规范）】\n"
                + special
            )
        resp = await invoke_guarded(
            model,
            [
                ("system", REPORT_GENERATOR_PROMPT),
                ("user", user_content),
            ],
            config=config,
            project_name=project,
        )
        content = getattr(resp, "content", resp)
        md = _strip_markdown_fence(content if isinstance(content, str) else str(content))
        if not md:
            md = (
                f"# 恶意样本综合参考手册：{project}\n\n"
                "> 数据不足：报告生成模型未返回有效内容，请以黑板上的 summary/artifact 为准。"
            )
            bb_log_event("report_generator_empty_output", {"fallback": True}, project)

        report_path = board_path(project, REPORT_MD_FILENAME)
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(md + "\n")

        bb_write_artifact(
            "p4_final_report_meta",
            {
                "status": "success",
                "report_path": report_path,
                "generated_at": _now_iso(),
                "source_refs": {
                    "final_report_ref": state.get("final_report_ref", ""),
                    "verification_summary": "bb://summary/verification_summary",
                    "shard_report_count": len(state.get("shard_reports", [])),
                },
            },
            project,
        )
        bb_checkpoint("report_generated", project)
        return {"report_md_path": report_path}

    return report_generator_node
