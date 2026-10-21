"""阶段门节点：预提取、知识路由与 HITL 审批门。"""
import os
from typing import Optional
from uuid import uuid4

from graph.state import AnalysisState
from tools.blackboard_tools import _now_iso
from tools.entry_models import ReviewStatus, enum_to_int, normalize_asm_address
from tools.entry_tools import (
    bb_append_version,
    bb_build_context,
    bb_checkpoint,
    bb_get_runtime,
    bb_load_checkpoint,
    bb_log_event,
    bb_query_entries,
    bb_review_entries,
    bb_set_runtime,
)
from tools.file_loaders import detect_sample_type, pre_extract_sample
from workers.knowledge import KNOWLEDGE_REGISTRY, load_knowledge, match_guides


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
