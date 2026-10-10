"""Web UI 审查面板后端（FastAPI）。

把 Phase 2 的 HITL 审批门渲染为可视化审查面板：启动分析、轮询状态、
展示审批门 interrupt 负载、提交 CONFIRM / MODIFY 人工决定（内部转为
``Command(resume=...)`` 恢复图执行）。

图构建与 checkpointer 逻辑复用 main.py 的公共函数（``make_saver_cm`` /
``collect_pending_interrupts`` / ``resolve_sample_export_dir``），图状态持久化在
``data/output/{project}/checkpoints.db``（thread_id = 项目名）。每次推进图
（start / decision）都新开一次 saver 连接，推进到停点（审批门 interrupt 或 END）
即释放，因此服务重启后只要 checkpoints.db 还在，status / review / decision
对历史项目照常工作（审批现场经 thread_id 机制恢复）。

启动：``python -m webui.server``；监听地址/端口取 config.yaml 的 ``webui.host`` /
``webui.port``（默认 127.0.0.1:8300，环境变量 WEBUI_HOST / WEBUI_PORT 兜底）。
"""
import asyncio
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from langgraph.types import Command
from pydantic import BaseModel

from graph import build_graph
from graph_nodes import REPORT_MD_FILENAME
from main import (
    collect_pending_interrupts,
    make_saver_cm,
    resolve_sample_export_dir,
)
from tools.blackboard_tools import board_path
from tools.docs_tools import user_md_append_answer, user_md_read

# === LLM 注入（测试用；None 表示按 config.yaml 构造真实模型）===

_LLM = None


def set_llm(llm) -> None:
    """注入 chat model 覆盖项（等价于 graph_nodes.set_llm，但只作用于 Web UI 构建的图）。"""
    global _LLM
    _LLM = llm


# === 进程内运行注册表（服务重启后凭 checkpoints.db 恢复审批视图）===

@dataclass
class RunRecord:
    """一次分析运行的进程内记录。

    task 推进到停点（审批门挂起 / 图结束 / 异常）即完成；此后项目状态以
    checkpoints.db 中的图快照为准。
    """

    project: str
    task: Optional[asyncio.Task] = None  # 当前推进任务（None 或已 done 表示空闲）
    error: Optional[str] = None          # 最近一次推进的异常描述
    started_at: float = field(default_factory=time.time)


RUNS: dict[str, RunRecord] = {}
_registry_lock = asyncio.Lock()


async def _advance(project: str, graph_input) -> None:
    """推进图到下一个停点（审批门 interrupt 或 END），中间状态由 checkpointer 持久化。

    graph_input 为初始 state dict（fresh 启动）或 ``Command(resume=...)``（审批恢复）。
    异常不抛出，写入 record.error 由 /status 暴露。

    每次推进新建 TokenStatsCallback 并注册（token 预算闸门的数据源）：
    计数按单次推进累计，跨推进（审批恢复后）的历史用量不继承——
    CLI 一路跑到底不受影响，Web UI 分段推进时闸门以下一段的增量为准。
    """
    from observability import TokenStatsCallback, register_callback

    record = RUNS[project]
    try:
        async with make_saver_cm(project) as saver:
            graph = build_graph(llm=_LLM, checkpointer=saver)
            token_callback = TokenStatsCallback(project)
            register_callback(project, token_callback)
            config = {
                "configurable": {"thread_id": project},
                "callbacks": [token_callback],
            }
            await graph.ainvoke(graph_input, config=config)
        record.error = None
    except Exception as exc:  # 后台任务必须兜底，失败经 /status 的 failed 状态暴露
        record.error = f"{type(exc).__name__}: {exc}"


async def _load_snapshot(project: str):
    """从 checkpoints.db 读取图状态快照；无 checkpoint（或为空）时返回 None。

    每次调用新开一次 saver 连接（同一 sqlite 文件可反复开关），因此服务重启后
    对历史项目的查询也能工作。
    """
    db_path = board_path(project, "checkpoints.db")
    if not os.path.exists(db_path):
        return None
    async with make_saver_cm(project) as saver:
        graph = build_graph(llm=_LLM, checkpointer=saver)
        snapshot = await graph.aget_state({"configurable": {"thread_id": project}})
    if not snapshot.values and not snapshot.next:
        return None
    return snapshot


def _is_running(record: Optional[RunRecord]) -> bool:
    return record is not None and record.task is not None and not record.task.done()


async def _derive_status(project: str) -> dict:
    """推导项目当前状态：running / awaiting_approval / completed / failed / interrupted / not_found。"""
    record = RUNS.get(project)
    if _is_running(record):
        return {"project": project, "status": "running"}
    if record is not None and record.error:
        return {"project": project, "status": "failed", "error": record.error}
    snapshot = await _load_snapshot(project)
    if snapshot is None:
        return {"project": project, "status": "not_found"}
    if collect_pending_interrupts(snapshot):
        return {"project": project, "status": "awaiting_approval"}
    if snapshot.next:
        # 有后续节点但没有挂起中断：上次进程在图运行途中退出留下的半成品
        return {"project": project, "status": "interrupted"}
    return {
        "project": project,
        "status": "completed",
        "report_md_path": snapshot.values.get("report_md_path"),
        "phase2_human_decision": snapshot.values.get("phase2_human_decision"),
    }


# === 请求模型与项目名校验 ===

# 项目名是黑板与 checkpoints.db 的子目录名，拒绝路径穿越字符（允许中文项目名）
_PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9._\-一-鿿]+$")


def _check_project_name(project: str) -> str:
    if not project or not _PROJECT_NAME_RE.match(project) or ".." in project:
        raise HTTPException(status_code=400, detail=f"非法项目名: {project!r}")
    return project


class StartRequest(BaseModel):
    """启动分析的请求体（参数语义与 CLI 的 -p / -i / -r / --focus / --exclude 一致）。"""

    project_name: str
    input_name: Optional[str] = None  # data/input/ 下的导出目录名，可省略 _export_for_ai 后缀
    resume: bool = False              # 黑板层断点续跑（跳过 Phase -1）
    focus: Optional[str] = None       # C2 用户重点关注领域（逗号分隔），缺省回退 config.yaml analysis.focus
    exclude: Optional[str] = None     # C2 用户排除领域（不深入静态过程），缺省回退 config.yaml analysis.exclude


class DecisionRequest(BaseModel):
    """人工决定：CONFIRM 直接放行；MODIFY 附带函数地址列表；
    其余任意字符串原样透传为 resume 文本（供 token 预算闸门等其他 interrupt 放行）。"""

    decision: str                      # CONFIRM / MODIFY / 其他任意放行文本
    functions: Optional[list[str]] = None  # MODIFY 时要分析的函数地址列表


class UsermdReplyRequest(BaseModel):
    """USER.md 异步沟通回复：只落盘到 docs/{project}/USER.md，不影响图运行。"""

    question_no: int                   # USER.md 中的编号问题序号
    answer: str                        # 用户回答内容（写入"用户回答："代码块）


# === FastAPI 应用 ===

app = FastAPI(title="RevAgent Web UI 审查面板", version="0.1.0")


@app.post("/api/analysis/start", status_code=202)
async def start_analysis(req: StartRequest) -> dict:
    """启动一次分析（后台 asyncio 任务跑图，推进到审批门或结束即停）。

    同项目已有运行中任务、正等待审批或已完成时返回 409 与当前状态提示。
    """
    project = _check_project_name(req.project_name)
    async with _registry_lock:
        record = RUNS.get(project)
        if _is_running(record):
            raise HTTPException(status_code=409, detail=f"项目 {project} 正在运行中")
        snapshot = await _load_snapshot(project)
        if snapshot is not None:
            if collect_pending_interrupts(snapshot):
                raise HTTPException(
                    status_code=409,
                    detail=f"项目 {project} 正等待人工审批，请改用 decision 接口提交决定",
                )
            if not snapshot.next:
                raise HTTPException(
                    status_code=409,
                    detail=f"项目 {project} 已分析完成；如需重跑请更换项目名",
                )
            raise HTTPException(
                status_code=409,
                detail=f"项目 {project} 上次运行中途退出且不在审批门，暂不支持从此处恢复",
            )
        try:
            export_dir = resolve_sample_export_dir(project, input_name=req.input_name)
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        record = RunRecord(project=project)
        RUNS[project] = record
        initial_state = {
            "sample_project_name": project,
            "sample_export_dir": export_dir,
            "resume": req.resume,
        }
        # C2 用户分析优先级：请求未显式给出时回退 config.yaml（analysis.focus / exclude）
        from config import cfg
        focus = req.focus if req.focus is not None else cfg("analysis.focus", env="FOCUS")
        exclude = req.exclude if req.exclude is not None else cfg("analysis.exclude", env="EXCLUDE")
        if focus:
            initial_state["user_focus"] = focus
        if exclude:
            initial_state["user_exclude"] = exclude
        record.task = asyncio.create_task(_advance(project, initial_state))
    return {"project": project, "status": "running"}


@app.get("/api/analysis/{project}/status")
async def get_status(project: str) -> dict:
    """查询图当前状态（服务重启后凭 checkpoints.db 推导，不会因注册表丢失而报错）。"""
    _check_project_name(project)
    return await _derive_status(project)


@app.get("/api/analysis/{project}/review")
async def get_review(project: str) -> dict:
    """审批门负载详情：interrupt 的 message + 行为定型结论 + 高风险指标 + Top 20 候选函数。"""
    _check_project_name(project)
    if _is_running(RUNS.get(project)):
        raise HTTPException(status_code=409, detail="项目正在运行中，尚未到达审批门")
    snapshot = await _load_snapshot(project)
    interrupts = collect_pending_interrupts(snapshot) if snapshot is not None else []
    if not interrupts:
        raise HTTPException(status_code=409, detail="项目当前不在审批门（无待审批负载）")

    payload = interrupts[0].value
    if not isinstance(payload, dict):
        payload = {"message": payload}
    values = snapshot.values
    function_boundary = values.get("function_boundary_analysis") or {}
    string_analysis = values.get("string_analysis") or {}
    api_behavior = values.get("api_behavior_analysis") or {}

    # 高风险指标计数与 graph_nodes.build_review_message 保持同一口径
    high_risk_strings = len([
        s for s in string_analysis.get("suspicious_patterns", [])
        if isinstance(s, dict) and s.get("risk_level") == "high"
    ])
    high_risk_apis = len([
        a for a in api_behavior.get("suspicious_apis", [])
        if isinstance(a, dict) and a.get("threat_category") in ["进程注入", "持久化", "网络通信"]
    ])

    return {
        "project": project,
        "kind": payload.get("kind"),
        "message": payload.get("message"),
        "error": payload.get("error"),
        "review": {
            "behavior_profile": values.get("behavior_profile") or {},
            "high_risk_strings": high_risk_strings,
            "high_risk_apis": high_risk_apis,
            "candidates": function_boundary.get("candidates", [])[:20],
            "total_functions": function_boundary.get("total_functions", 0),
            "recommended_top_n": function_boundary.get("recommended_top_n", 20),
        },
    }


@app.post("/api/analysis/{project}/decision")
async def post_decision(project: str, req: DecisionRequest) -> dict:
    """提交人工决定，内部转为 ``Command(resume=...)`` 恢复图执行（后台推进到下一停点）。

    CONFIRM / MODIFY 维持原协议（MODIFY 拼地址列表）；其余任意非空字符串
    原样透传为 resume 文本——token 预算闸门（kind=token_budget）等非审批门
    interrupt 由前端发送任意放行文本（如 CONTINUE）恢复。
    """
    _check_project_name(project)
    decision = req.decision.strip()
    if not decision:
        raise HTTPException(status_code=400, detail="decision 不能为空")
    upper = decision.upper()
    if upper == "CONFIRM":
        resume_text = "CONFIRM"
    elif upper == "MODIFY":
        functions = [f.strip() for f in (req.functions or []) if f and f.strip()]
        if not functions:
            raise HTTPException(status_code=400, detail="MODIFY 必须提供非空 functions 地址列表")
        resume_text = "MODIFY " + ",".join(functions)
    else:
        # CONFIRM/MODIFY 之外原样透传（接收方节点自行解释；审批门会把无法识别的
        # 回复计入无效尝试并重新挂起，不破坏审批现场）
        resume_text = decision

    async with _registry_lock:
        if _is_running(RUNS.get(project)):
            raise HTTPException(status_code=409, detail="项目正在运行中，稍后再试")
        snapshot = await _load_snapshot(project)
        if snapshot is None or not collect_pending_interrupts(snapshot):
            raise HTTPException(status_code=409, detail="项目当前不在审批门，无法提交决定")
        record = RUNS.get(project)
        if record is None:
            # 服务重启后直接对历史项目提交决定：补建注册表记录
            record = RunRecord(project=project)
            RUNS[project] = record
        record.error = None
        record.task = asyncio.create_task(_advance(project, Command(resume=resume_text)))
    return {"project": project, "status": "running", "resumed": resume_text}


@app.get("/api/analysis/{project}/report")
async def get_report(project: str) -> dict:
    """读取 data/output/{project}/final_report.md，返回 Markdown 文本。"""
    _check_project_name(project)
    path = board_path(project, REPORT_MD_FILENAME)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="最终报告尚未生成")
    with open(path, encoding="utf-8") as f:
        content = f.read()
    return {"project": project, "path": path, "markdown": content}


# === USER.md 异步沟通通道（纯落盘，与图运行解耦）===

@app.get("/api/analysis/{project}/usermd")
async def get_usermd(project: str) -> dict:
    """读取 docs/{project}/USER.md 原文与解析结果（不存在时自动建骨架）。

    异步通道：任何运行状态都可查询——Agent（orchestrator / 主题节点）运行中
    写入的问题即时可见，不要求项目到达审批门。
    """
    _check_project_name(project)
    result = user_md_read(project)
    if result.get("status") != "success":
        raise HTTPException(status_code=500, detail=result.get("error") or "USER.md 读取失败")
    return {
        "project": project,
        "path": result["path"],
        "content": result["content"],
        "questions": result["questions"],
        "focus": result["focus"],
    }


@app.post("/api/analysis/{project}/usermd/reply")
async def post_usermd_reply(project: str, req: UsermdReplyRequest) -> dict:
    """把用户回答追加到指定编号问题的"用户回答："代码块（只落盘，不影响图运行）。

    Agent 在下一波主题任务构建 prompt 前重新读取 USER.md，回答届时生效。
    """
    _check_project_name(project)
    if not req.answer.strip():
        raise HTTPException(status_code=400, detail="回答内容不能为空")
    result = user_md_append_answer(project, req.question_no, req.answer.strip())
    if result.get("status") != "success":
        status_code = 404 if result.get("reason") == "question_not_found" else 500
        raise HTTPException(
            status_code=status_code,
            detail=result.get("error") or f"回答写入失败: {result.get('reason')}",
        )
    return {"project": project, **result}


# 静态托管单页面前端（API 路由先注册，/api/* 优先匹配，其余落到静态页）
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="webui")


def main() -> None:
    """启动 Web UI 服务（python -m webui.server）。"""
    from config import cfg, cfg_int

    host = cfg("webui.host", env="WEBUI_HOST", default="127.0.0.1")
    port = cfg_int("webui.port", env="WEBUI_PORT", default=8300)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
