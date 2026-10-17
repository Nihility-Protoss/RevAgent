"""LangGraph 节点工厂与业务节点。
"""
import copy
import json
import os
from typing import Any, Optional
from uuid import uuid4

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from langchain.chat_models import init_chat_model
from langchain_core.messages.utils import convert_to_messages, count_tokens_approximately
from langchain_core.runnables import RunnableConfig

from config import cfg, cfg_int
from state import AnalysisState
from tools.agent_tools import get_agent_tools
from tools.blackboard_tools import (
    _now_iso,
    load_function_data,
)
from tools.entry_models import (
    ConclusionValidationStatus,
    DataValidationStatus,
    ReviewStatus,
    SubjectValidationStatus,
    WorkerOutput,
    enum_to_int,
    normalize_asm_address,
)
from tools.entry_tools import (
    bb_append_version,
    bb_build_context,
    bb_checkpoint,
    bb_create_entry,
    bb_find_operation,
    bb_get_entry,
    bb_get_runtime,
    bb_load_checkpoint,
    bb_log_event,
    bb_query_entries,
    bb_review_entries,
    bb_set_runtime,
    bb_write_worker_output,
)
from tools.file_loaders import detect_sample_type, pre_extract_sample
from workers.knowledge import KNOWLEDGE_REGISTRY, load_knowledge, match_guides
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt
from workers.phase4.synthesis_agent import AGGREGATOR_PROMPT, SHARD_SYNTHESIS_PROMPT
from workers.specs import WorkerSpec

# === LLM 构造（环境变量与 ADK 版保持一致）===

_LLM = None


def get_llm():
    """返回共享 chat model（优先级：config.yaml > 环境变量 > 默认值）。
    """
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
    """注入一个模型实例（供测试离线运行使用）。
    """
    global _LLM
    _LLM = llm


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


async def invoke_guarded(model, messages: list, config: Optional[RunnableConfig] = None):
    """带上下文预算约束的 ainvoke（默认 128k）。
    """
    return await model.ainvoke(enforce_context_budget(messages), config=config)


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


# === Worker 节点工厂（统一 WorkerOutput 投影） ===


def _resolve_run_id(state: AnalysisState) -> str:
    """解析当前运行的 run_id：优先图状态，其次黑板 runtime，最后生成并持久化。"""
    project = state["sample_project_name"]
    run_id = state.get("run_id") or bb_get_runtime("run_id", project)
    if not run_id:
        run_id = f"run-{uuid4().hex[:8]}"
        bb_set_runtime("run_id", run_id, project)
    return run_id


def _worker_phase(worker_name: str) -> str:
    """worker 名 → 所属阶段（与 tools.entry_tools 的投影分派保持一致）。"""
    from tools.entry_tools import _WORKER_PHASES

    phase = _WORKER_PHASES.get(worker_name)
    if phase is None:
        raise ValueError(f"未知 worker: {worker_name}")
    return phase


def build_worker_task(spec: WorkerSpec, state: AnalysisState, run_id: str) -> str:
    """构建发给 Worker Agent 的任务文本。

    任务文本必须包含本次调用的幂等键公式（``{run_id}:{phase}:{worker_name}:{subject_key}``
    及代入具体值后的前缀），full 模式 Agent 主动写入时才能与框架兜底投影使用同一公式。
    """
    project = state["sample_project_name"]
    export_dir = state.get("sample_export_dir", "")
    phase = _worker_phase(spec.name)
    key_prefix = f"{run_id}:{phase}:{spec.name}"
    return (
        f"分析样本: {project}, "
        f"导出目录: {export_dir}\n"
        f"本次运行 run_id: {run_id}，你的阶段: {phase}，worker 名: {spec.name}。\n"
        f"你的产物将由框架按幂等键公式写入黑板: "
        f"{{run_id}}:{{phase}}:{{worker_name}}:{{subject_key}}，"
        f"本次调用即 {key_prefix}:<subject_key>。"
        f"若你自行调用写入工具，必须使用相同的键公式与本次 run_id/阶段/worker 名。"
    )


def _project_worker_output(spec: WorkerSpec, payload: dict,
                           project_name: str, run_id: str) -> dict:
    """把 Worker 产物投影到黑板；失败时记录 runtime 事件但不抛出。

    投影错误（未知发现类别、scheduler 地址未解析等）以 ``worker_projection_failed``
    事件写入黑板 runtime 日志，保证失败可见；节点仍然继续执行。
    """
    result = bb_write_worker_output(spec.name, payload, project_name, run_id)
    if result.get("status") == "error":
        bb_log_event(
            "worker_projection_failed",
            {
                "worker": spec.name,
                "reason": result.get("reason"),
                "error": result.get("error"),
            },
            project_name,
        )
    return result


def make_worker_node(spec: WorkerSpec, llm=None):
    """把一个 WorkerSpec 编译为 LangGraph 节点函数。

    Agent 按 ``(project_name, run_id, export_dir, tool_mode)`` 创建并缓存；
    工具集来自 ``get_agent_tools(spec.name, ...)`` 按角色动态注入。
    结构化输出（WorkerOutput）经 ``bb_write_worker_output`` 投影为版本化条目，
    写入幂等键为 ``{run_id}:{phase}:{worker_name}:{subject_key}``；
    节点返回 ``{}``，不再向图状态写 output_key payload。
    """
    _cache: dict = {}

    def _agent(project_name: str, run_id: str, export_dir: str, tool_mode: str):
        key = (project_name, run_id, export_dir, tool_mode)
        if key not in _cache:
            model = llm or get_llm()
            _cache[key] = create_agent(
                model=model,
                tools=get_agent_tools(
                    spec.name, project_name, run_id, export_dir, mode=tool_mode
                ),
                system_prompt=spec.instruction,
                response_format=spec.output_schema,
                # ReAct 历史接近上下文上限（128k 的 75%）时自动摘要压缩
                middleware=[
                    SummarizationMiddleware(
                        model,
                        trigger=("tokens", _summary_trigger_tokens()),
                        keep=("messages", 20),
                    )
                ],
            )
        return _cache[key]

    async def node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        project = state["sample_project_name"]
        export_dir = state.get("sample_export_dir", "")
        run_id = _resolve_run_id(state)
        tool_mode = state.get("tool_mode") or cfg("agents.tool_mode", default="minimal")
        task = build_worker_task(spec, state, run_id)
        result = await _agent(project, run_id, export_dir, tool_mode).ainvoke(
            {"messages": [("user", task)]}, config=config
        )
        structured = result.get("structured_response")
        if structured is not None:
            payload = (
                structured.model_dump() if hasattr(structured, "model_dump") else dict(structured)
            )
        else:
            payload = parse_json_loose(result["messages"][-1].content)

        if isinstance(payload, dict):
            _project_worker_output(spec, payload, project, run_id)
        else:
            bb_log_event(
                "worker_output_invalid",
                {"worker": spec.name, "type": type(payload).__name__},
                project,
            )
        return {}

    node.__name__ = spec.name
    return node


# === Phase -1: 预提取（纯函数节点）===

def pre_extract_node(state: AnalysisState) -> dict:
    """把 Phase -1 预提取结果写入黑板（resume 时跳过）。

    fresh 运行生成新的 run_id（uuid4().hex）并写入 runtime；resume 时从 runtime
    恢复原 run_id，缺少 run_id 抛出 RuntimeError。checkpoint 与事件日志全部
    通过 runtime 工具保存，不再创建 meta/ 目录。
    """
    project = state["sample_project_name"]
    if state.get("resume"):
        existing = bb_load_checkpoint(project)
        if existing is not None:
            run_id = bb_get_runtime("run_id", project)
            if not run_id:
                raise RuntimeError("resume 缺少 run_id")
            bb_log_event(
                "run_start",
                {"mode": "resume", "phase": existing.get("current_phase")},
                project,
            )
            return {"run_id": run_id}

    run_id = uuid4().hex
    bb_set_runtime("run_id", run_id, project)
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
    return {"sample_type": sample_type, "run_id": run_id}


# === 知识路由（纯函数节点，逻辑照搬原 orchestrator.resolve_active_guides）===

def _latest_sample_arch_detection(project_name: str) -> dict:
    """查询最新的 sample 条目，提取其 payload.arch_detection；缺失时返回 {}。"""
    try:
        result = bb_query_entries(project_name, {"entry_type": "sample"}, limit=50)
        entries = result.get("data") or []
        if not entries:
            return {}
        head = (entries[-1].get("versions") or [{}])[0]
        arch = ((head.get("payload") or {}).get("arch_detection"))
        return arch if isinstance(arch, dict) else {}
    except Exception:
        return {}


def resolve_active_guides(project_name: str, arch_detection: Optional[dict] = None) -> dict:
    """解析本样本激活了哪些知识指南。

    若传入 arch_detection 则直接使用；否则查询黑板上最新的 sample 条目，
    取其 payload.arch_detection。结果持久化到 runtime.active_guides。
    永不抛异常：任何失败都回退到 windows_pe 基线。
    """
    if arch_detection is not None:
        arch = arch_detection or {}
    else:
        arch = _latest_sample_arch_detection(project_name)

    if not arch:
        bb_log_event(
            "active_guides_default_fallback",
            {"reason": "sample entry or arch_detection missing"},
            project_name,
        )

    names = match_guides(arch)
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
    bb_set_runtime("active_guides", doc, project_name)
    return doc


def resolve_guides_node(state: AnalysisState) -> dict:
    """依据 Phase 0 的 arch_detection 解析激活的知识指南。

    arch_detection 直接查询黑板上最新的 sample 条目（Phase 0 字符串 Worker
    的产物），不再读取图状态。
    """
    resolve_active_guides(state["sample_project_name"])
    return {}


def _load_active_guides_text(project_name: str) -> str:
    """拼接所有激活指南的完整文本，用于注入 prompt。

    只读取 runtime.active_guides；缺失或内容异常时回退 __active__（基线指南）。
    """

    def _fallback() -> str:
        result = load_knowledge("__active__", project_name)
        return result.get("content", "") if result.get("status") == "success" else ""

    doc = bb_get_runtime("active_guides", project_name, default={}) or {}
    guides = doc.get("guides")
    if not isinstance(guides, list):
        return _fallback()
    parts = []
    for g in guides:
        if not isinstance(g, dict):
            continue
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

样本判定: {sample_assessment} (置信度: {confidence})
高风险字符串指标: {high_risk_strings}
高风险 API 指标: {high_risk_apis}
候选函数: {candidate_count}

请审查以上分析结论，确认：
1. 行为定型是否合理
2. 候选函数列表是否需要调整（排除/补充）
3. 是否需要继续深入分析特定函数

回复格式:
- CONFIRM  (同意继续，使用推荐候选函数)
- MODIFY <addr1>,<addr2>,...  (指定要分析的函数地址列表，逗号分隔)

例如: MODIFY 0x401000,0x402000,0x403000
"""


# 视为高风险的 API 威胁类别（与 Phase 0 API profiler 的 threat_category 取值一致）
_HIGH_RISK_API_CATEGORIES = {"进程注入", "持久化", "网络通信"}


def build_review_message(state: dict) -> str:
    """基于黑板 ``human_review`` 上下文构建人类可读的审查消息。

    行为判定取 sample 条目的结论，风险指标与候选统计从 finding / function
    条目的 head 版本汇总，不再依赖图状态中的 payload。
    """
    project = state["sample_project_name"]
    context = bb_build_context("human_review", project, token_budget=6000)
    entries = context.get("entries") or []

    sample_assessment = "Unknown"
    confidence = "low"
    high_risk_strings = 0
    high_risk_apis = 0
    candidate_count = 0

    for item in entries:
        entry_type = item.get("entry_type")
        payload = item.get("payload") or {}
        if entry_type == "sample":
            sample_assessment = item.get("conclusion") or sample_assessment
            confidence = item.get("confidence") or confidence
        elif entry_type == "finding":
            details = payload.get("details") or {}
            if payload.get("category") == "string" and details.get("risk_level") == "high":
                high_risk_strings += 1
            if (
                payload.get("category") == "api"
                and details.get("threat_category") in _HIGH_RISK_API_CATEGORIES
            ):
                high_risk_apis += 1
        elif entry_type == "function":
            candidate_count += 1

    return APPROVAL_MESSAGE_TEMPLATE.format(
        sample_assessment=sample_assessment,
        confidence=confidence,
        high_risk_strings=high_risk_strings,
        high_risk_apis=high_risk_apis,
        candidate_count=candidate_count,
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


def prompt_human(message: str) -> str:
    """从分析师读取一行回复（模块级定义，便于测试 monkeypatch）。
    """
    return input(message)


def _latest_decision_entry(project_name: str) -> Optional[dict]:
    """查询最新的调度决策条目（按创建顺序返回，取最后一个）。"""
    data = bb_query_entries(project_name, {"entry_type": "decision"}, limit=50).get("data") or []
    return data[-1] if data else None


def _normalize_modify_addresses(project_name: str, addrs: list[str]) -> tuple[list[dict], list[str]]:
    """把 MODIFY 地址列表解析为函数 ref 列表；未知地址记入 unknown_addresses。"""
    refs: list[dict] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for addr in addrs:
        try:
            normalized = normalize_asm_address(addr)
        except ValueError:
            unknown.append(addr)
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        data = bb_query_entries(
            project_name, {"entry_type": "function", "subject.key": normalized}, limit=1
        ).get("data") or []
        if not data:
            unknown.append(normalized)
        else:
            refs.append({"entry_id": data[0]["entry_id"], "version": data[0]["head_version"]})
    return refs, unknown


def _finalize_human_review(
    project_name: str,
    run_id: str,
    decision_entry: dict,
    selected_refs: list[dict],
    summary: dict,
) -> None:
    """对选中函数的当前 head 写入人工审查，并把 decision 指向审查后的新版本。

    未选中的函数条目保持原审查状态；decision 自身追加 change_reason=review
    的版本，payload 中的 selected_function_refs 更新为审查后的精确版本。
    """
    head = decision_entry["versions"][0]
    payload = head.get("payload") or {}

    reviewed_refs = selected_refs
    if selected_refs:
        review_result = bb_review_entries(
            selected_refs, "confirmed", project_name,
            reviewer="human", note="HITL approval gate",
        )
        if review_result.get("status") == "success":
            reviewed_refs = review_result["reviewed_refs"]
        else:
            bb_log_event(
                "approval_gate_review_failed",
                {"reason": review_result.get("reason"), "error": review_result.get("error")},
                project_name,
            )

    producer = head.get("producer") or {
        "phase": "phase2", "agent": "scheduler", "run_id": run_id,
    }
    changes = {
        "payload": {
            "action": payload.get("action", ""),
            "selected_function_refs": reviewed_refs,
            "summary": summary,
        },
        "review": {
            "status": enum_to_int(ReviewStatus, "confirmed"),
            "reviewer": "human",
            "reviewed_at": _now_iso(),
            "note": "HITL approval gate",
        },
    }
    bb_append_version(
        decision_entry["entry_id"],
        decision_entry["head_version"],
        changes,
        producer,
        project_name,
        f"{run_id}:phase2:scheduler:phase2:human-review",
        change_reason="review",
    )


def approval_gate_node(state: AnalysisState) -> dict:
    """Phase 2→3 人工审批门（CLI）。审查结果直接持久化为条目版本，节点返回 {}。

    CONFIRM 采用调度决策当前的 selected_function_refs；MODIFY 规范化地址后解析为
    函数条目，不存在的地址写入 decision.payload.summary.unknown_addresses（不创建
    空函数）。3 次无效回复后默认 CONFIRM，走相同的写入路径。
    """
    project = state["sample_project_name"]
    run_id = state.get("run_id") or ""
    decision_entry = _latest_decision_entry(project)
    if decision_entry is None:
        bb_log_event("approval_gate_no_decision", {"run_id": run_id}, project)
        return {}

    head = decision_entry["versions"][0]
    payload = head.get("payload") or {}
    summary = dict(payload.get("summary") or {})
    default_refs = list(payload.get("selected_function_refs") or [])

    print(build_review_message(state))
    selected_refs: Optional[list[dict]] = None
    for _attempt in range(3):
        reply = prompt_human("请回复 CONFIRM 或 MODIFY <addr1>,<addr2>,...: ")
        decision, addrs = parse_approval_reply(reply)
        if decision == "confirm":
            selected_refs = list(default_refs)
            break
        if decision == "modify":
            selected_refs, unknown = _normalize_modify_addresses(project, addrs or [])
            if unknown:
                summary["unknown_addresses"] = unknown
            break
        print(f"[ERROR] 无法识别回复: {reply.strip()}，请使用 CONFIRM 或 MODIFY 格式。")

    if selected_refs is None:
        # 3 次无效输入默认 CONFIRM：与正常 CONFIRM 使用相同的写入路径
        selected_refs = list(default_refs)

    _finalize_human_review(project, run_id, decision_entry, selected_refs, summary)
    return {}


# === Phase 3: 函数级深度分析（同条目追加版本，Send 并行留待 Step 3） ===

# Phase 3 分析的幂等键公式：与 Worker 投影公式保持一致
_PHASE3_WORKER = "function_deep_analyzer"
_PHASE3_IDEMPOTENCY_KEY = "{run_id}:phase3:{worker}:{entry_id}"


def _load_latest_decision_refs(project_name: str) -> list[dict]:
    """读取最新调度决策中人工确认过的 selected_function_refs。"""
    data = bb_query_entries(project_name, {"entry_type": "decision"}, limit=50).get("data") or []
    if not data:
        return []
    head = data[-1]["versions"][0]
    return list((head.get("payload") or {}).get("selected_function_refs") or [])


def _function_index_contains(export_dir: str, addr: str) -> bool:
    """判断函数索引文件中是否包含指定地址（宽松的大小写匹配）。"""
    index_path = os.path.join(export_dir, "function_index.txt")
    if not os.path.exists(index_path):
        return False
    try:
        with open(index_path, "r", encoding="utf-8", errors="ignore") as f:
            return addr.lower() in f.read().lower()
    except OSError:
        return False


def _validation_with_subject_status(validation: dict, subject_status: Optional[str] = None) -> dict:
    """把公开视图（枚举小写字符串名）的 validation 转换为存储整数视图。

    ``subject_status`` 非空时覆盖 subject 层状态；三层状态全部经 enum_to_int
    转换，保证 append_version 的 pydantic 校验通过。
    """
    validation = copy.deepcopy(validation) or {}
    data = validation.get("data") or {}
    subject = validation.get("subject") or {}
    conclusion = validation.get("conclusion") or {}
    if subject_status is not None:
        subject["status"] = subject_status
    return {
        "data": {
            "status": enum_to_int(DataValidationStatus, data.get("status", "valid")),
            "errors": list(data.get("errors") or []),
        },
        "subject": {
            "status": enum_to_int(SubjectValidationStatus, subject.get("status", "unknown")),
            "evidence_refs": list(subject.get("evidence_refs") or []),
        },
        "conclusion": {
            "status": enum_to_int(ConclusionValidationStatus, conclusion.get("status", "unverified")),
            "evidence_refs": list(conclusion.get("evidence_refs") or []),
        },
    }


def _build_phase3_changes(
    head: dict,
    func_data: dict,
    export_dir: str,
    addr: str,
    output: WorkerOutput,
) -> dict:
    """把函数 head 与新的 WorkerOutput 归并为一次 change_reason=analysis 的版本变更。

    - 成功：head.payload.candidate 保留，payload.analysis 写入新分析结果；
      代码片段与函数索引均存在时 validation.subject.status 置为 valid。
    - 数据不足：仍追加版本以保留分析历史，但 validation.subject.status 置为
      insufficient_data，payload 保持 head 不变。
    """
    head_payload = head.get("payload") or {}
    annotations = {**(head.get("annotations") or {}), **(output.annotations or {})}

    if output.status == "insufficient_data":
        return {
            "conclusion": output.conclusion,
            "confidence": output.confidence,
            "payload": head_payload,
            "evidence_refs": list(head.get("evidence_refs") or []),
            "annotations": annotations,
            "validation": _validation_with_subject_status(
                head.get("validation"), "insufficient_data"
            ),
        }

    has_code = bool(
        (func_data.get("decompile_snippet") or "").strip()
        or (func_data.get("disassembly_snippet") or "").strip()
    )
    analysis = {
        key: output.payload.get(key)
        for key in ("functionality", "key_apis", "suspicious_behaviors",
                    "related_functions", "analysis_notes")
        if key in (output.payload or {})
    }
    new_payload = {**head_payload, "analysis": analysis}
    subject_status = None
    if has_code and _function_index_contains(export_dir, addr):
        subject_status = "valid"
    return {
        "conclusion": output.conclusion,
        "confidence": output.confidence,
        "payload": new_payload,
        "evidence_refs": list(output.evidence_refs or []),
        "annotations": annotations,
        "validation": _validation_with_subject_status(head.get("validation"), subject_status),
    }


def make_phase3_node(llm=None):
    """构建 Phase 3 逐函数深度分析节点（串行循环）。

    候选函数取自黑板上最新调度决策的 selected_function_refs（已由审批门审查）；
    每个函数的分析结果作为 change_reason=analysis 的版本追加到同一函数条目，
    幂等键为 ``{run_id}:phase3:function_deep_analyzer:{entry_id}``，重跑不产生
    新的 LLM 调用。节点返回 {}，分析结果只落在条目版本上。
    """

    async def phase3_deep_analysis_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm()
        project = state["sample_project_name"]
        run_id = _resolve_run_id(state)
        export_dir = state.get("sample_export_dir", "")

        selected_refs = _load_latest_decision_refs(project)
        if not selected_refs:
            bb_log_event("phase3_skipped", {"reason": "no_selected_functions"}, project)
            return {}

        guides_text = _load_active_guides_text(project)

        for ref in selected_refs:
            entry_id = ref["entry_id"]
            op_key = _PHASE3_IDEMPOTENCY_KEY.format(
                run_id=run_id, worker=_PHASE3_WORKER, entry_id=entry_id,
            )
            # 幂等：同 run 内已完成该函数的深度分析则整体跳过（不发起 LLM 调用）
            if bb_find_operation(op_key, project).get("data"):
                continue

            entry_view = bb_get_entry(entry_id, project)["data"]
            head = entry_view["versions"][0]
            addr = entry_view["subject"]["key"]
            func_name = (head.get("payload") or {}).get("func_name") or f"sub_{addr[2:]}"

            func_data = load_function_data(addr, export_dir)
            prompt = build_func_analysis_prompt(addr, func_name, func_data, guides=guides_text)
            resp = await invoke_guarded(model, [("user", prompt)], config=config)
            raw = parse_json_loose(getattr(resp, "content", resp))
            try:
                output = WorkerOutput.model_validate(raw)
            except Exception as exc:  # 结构化校验失败按 parse_failed 处理
                output = WorkerOutput(
                    status="parse_failed", conclusion=f"WorkerOutput 校验失败: {exc}",
                )

            if output.status == "parse_failed":
                # 不写版本，仅记录 runtime 失败；重跑会重新分析该函数
                bb_log_event(
                    "phase3_parse_failed",
                    {"entry_id": entry_id, "addr": addr, "raw": str(raw.get("raw", ""))[:200]},
                    project,
                )
                continue

            changes = _build_phase3_changes(head, func_data, export_dir, addr, output)
            producer = {"phase": "phase3", "agent": _PHASE3_WORKER, "run_id": run_id}
            bb_append_version(
                entry_id,
                entry_view["head_version"],
                changes,
                producer,
                project,
                op_key,
                change_reason="analysis",
            )
            bb_checkpoint(f"phase3_progress_{addr}", project)

        return {}

    return phase3_deep_analysis_node


# === Phase 4: 综合报告（Map-Reduce，分片串行为小模型稳定性保留） ===

# Phase 4 报告条目的幂等键公式：{run_id}:phase4:{agent}:{subject_key}
_PHASE4_SHARD_AGENT = "shard_synthesis"
_PHASE4_AGGREGATOR_AGENT = "aggregator"

# 单个分片 / 聚合上下文一次 LLM 调用的输入上限
_PHASE4_CONTEXT_BUDGET = 20000


def _validate_worker_output(raw: Any) -> WorkerOutput:
    """把模型原始输出校验为 WorkerOutput；失败时回退 parse_failed 占位。"""
    try:
        return WorkerOutput.model_validate(raw)
    except Exception as exc:  # 结构化校验失败按 parse_failed 处理
        return WorkerOutput(
            status="parse_failed", conclusion=f"WorkerOutput 校验失败: {exc}",
        )


def make_shard_synthesis_node(llm=None):
    """构建 Phase 4 的 map 节点：按页对 Phase 3 函数条目做分片综合。

    每次读取 ``phase4_overview``（Phase 0/1 sample/finding）上下文与一页
    ``phase4_shard``（Phase 3 函数条目，每页最多5个）上下文，两类条目作为
    prompt JSON 输入；每个分片写一条 report 条目（
    ``subject.key="shard:{index}"``、``payload.report_kind="shard"``），
    ``relation_refs`` 记录当前页所有输入条目的精确版本（entry_id + version）。
    幂等键 ``{run_id}:phase4:shard_synthesis:shard:{index}``：同一 run_id 重跑
    直接返回已有 report，不重复调用 LLM、不产生新页。节点返回 {}。
    """

    async def shard_synthesis_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        model = llm or get_llm()
        project = state["sample_project_name"]
        run_id = _resolve_run_id(state)

        overview = bb_build_context(
            "phase4_overview", project, token_budget=_PHASE4_CONTEXT_BUDGET,
        ).get("entries") or []

        cursor: Optional[str] = None
        shard_index = 0
        while True:
            page = bb_build_context(
                "phase4_shard", project, token_budget=_PHASE4_CONTEXT_BUDGET,
                cursor=cursor,
            )
            entries = page.get("entries") or []
            if not entries:
                break
            shard_index += 1
            subject_key = f"shard:{shard_index}"
            op_key = f"{run_id}:phase4:{_PHASE4_SHARD_AGENT}:{subject_key}"
            # 幂等：同 run 内该分片已综合则整体跳过（不发起 LLM 调用）
            if not bb_find_operation(op_key, project).get("data"):
                shard_context = {
                    "overview": overview,
                    "shard": entries,
                    "shard_index": shard_index,
                }
                resp = await invoke_guarded(
                    model,
                    [
                        ("system", SHARD_SYNTHESIS_PROMPT),
                        ("user", json.dumps(shard_context, ensure_ascii=False)),
                    ],
                    config=config,
                )
                raw = parse_json_loose(getattr(resp, "content", resp))
                output = _validate_worker_output(raw)
                if output.status == "parse_failed":
                    bb_log_event(
                        "phase4_shard_parse_failed",
                        {"shard_index": shard_index,
                         "raw": str(raw.get("raw", ""))[:200]},
                        project,
                    )
                else:
                    relation_refs = [
                        {"entry_id": item["entry_id"], "version": item["version"]}
                        for item in entries
                    ]
                    bb_create_entry(
                        "report", "report", subject_key,
                        {
                            "conclusion": output.conclusion,
                            "confidence": output.confidence,
                            "payload": {
                                "report_kind": "shard",
                                "shard_id": shard_index,
                                **(output.payload or {}),
                            },
                            "evidence_refs": list(output.evidence_refs),
                            "annotations": dict(output.annotations),
                            "relation_refs": relation_refs,
                        },
                        {"phase": "phase4", "agent": _PHASE4_SHARD_AGENT, "run_id": run_id},
                        project, op_key,
                    )
            cursor = page.get("next_cursor")
            if cursor is None:
                break

        if shard_index == 0:
            bb_log_event("phase4_no_functions", {"run_id": run_id}, project)
        return {}

    return shard_synthesis_node


def make_aggregator_node(llm=None):
    """构建 Phase 4 的 reduce 节点：把本 run 的分片报告聚合为最终报告。

    读取 ``phase4_overview`` 与 ``phase4_aggregate``（本 run 的 shard report
    条目），写 ``subject.key="final"``、``payload.report_kind="final"`` 的
    report 条目，``relation_refs`` 指向全部输入条目的精确版本；幂等键
    ``{run_id}:phase4:aggregator:final`` 保证同一 run 重跑不重复聚合。
    节点只返回 ``{"final_report_entry_id": entry_id}``，随后
    ``bb_checkpoint("phase4_complete")`` 强制落盘。
    """

    async def aggregator_node(state: AnalysisState, config: RunnableConfig = None) -> dict:
        project = state["sample_project_name"]
        run_id = _resolve_run_id(state)
        op_key = f"{run_id}:phase4:{_PHASE4_AGGREGATOR_AGENT}:final"

        found = bb_find_operation(op_key, project).get("data")
        if found:
            entry_id = found["entry_id"]
        else:
            model = llm or get_llm()
            overview = bb_build_context(
                "phase4_overview", project, token_budget=_PHASE4_CONTEXT_BUDGET,
            ).get("entries") or []
            shard_reports = bb_build_context(
                "phase4_aggregate", project, token_budget=_PHASE4_CONTEXT_BUDGET,
                run_id=run_id,
            ).get("entries") or []

            aggregate_context = {
                "overview": overview,
                "shard_reports": shard_reports,
            }
            resp = await invoke_guarded(
                model,
                [
                    ("system", AGGREGATOR_PROMPT),
                    ("user", json.dumps(aggregate_context, ensure_ascii=False)),
                ],
                config=config,
            )
            raw = parse_json_loose(getattr(resp, "content", resp))
            output = _validate_worker_output(raw)
            if output.status == "parse_failed":
                # 聚合失败不静默：写 runtime 事件并抛出，避免产出空最终报告
                bb_log_event(
                    "phase4_aggregate_parse_failed",
                    {"raw": str(raw.get("raw", ""))[:200]},
                    project,
                )
                raise RuntimeError(f"Phase 4 聚合输出校验失败: {output.conclusion}")
            relation_refs = [
                {"entry_id": item["entry_id"], "version": item["version"]}
                for item in overview + shard_reports
            ]
            created = bb_create_entry(
                "report", "report", "final",
                {
                    "conclusion": output.conclusion,
                    "confidence": output.confidence,
                    "payload": {
                        "report_kind": "final",
                        **(output.payload or {}),
                    },
                    "evidence_refs": list(output.evidence_refs),
                    "annotations": dict(output.annotations),
                    "relation_refs": relation_refs,
                },
                {"phase": "phase4", "agent": _PHASE4_AGGREGATOR_AGENT, "run_id": run_id},
                project, op_key,
            )
            entry_id = created["data"]["entry_id"]

        bb_checkpoint("phase4_complete", project)
        return {"final_report_entry_id": entry_id}

    return aggregator_node
