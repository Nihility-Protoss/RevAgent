"""Phase 4：综合报告（Map-Reduce）节点。"""
import json
from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from graph.runtime import get_llm, invoke_guarded, parse_json_loose
from graph.state import AnalysisState
from graph.workers import _resolve_run_id
from tools.entry_models import WorkerOutput
from tools.entry_tools import (
    bb_build_context,
    bb_checkpoint,
    bb_create_entry,
    bb_find_operation,
    bb_log_event,
)
from workers.phase4.synthesis_agent import AGGREGATOR_PROMPT, SHARD_SYNTHESIS_PROMPT


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
