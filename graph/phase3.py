"""Phase 3：函数级深度分析节点。"""
import copy
from typing import Optional

from langchain_core.runnables import RunnableConfig

from graph.gates import (
    _function_index_contains,
    _load_active_guides_text,
    _load_latest_decision_refs,
)
from graph.runtime import get_llm, invoke_guarded, parse_json_loose
from graph.state import AnalysisState
from graph.workers import _resolve_run_id
from tools.blackboard_tools import load_function_data
from tools.entry_models import (
    ConclusionValidationStatus,
    DataValidationStatus,
    SubjectValidationStatus,
    WorkerOutput,
    enum_to_int,
)
from tools.entry_tools import (
    bb_append_version,
    bb_checkpoint,
    bb_find_operation,
    bb_get_entry,
    bb_log_event,
)
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt


# === Phase 3: 函数级深度分析（同条目追加版本，Send 并行留待 Step 3） ===

# Phase 3 分析的幂等键公式：与 Worker 投影公式保持一致
_PHASE3_WORKER = "function_deep_analyzer"
_PHASE3_IDEMPOTENCY_KEY = "{run_id}:phase3:{worker}:{entry_id}"


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
