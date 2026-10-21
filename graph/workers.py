"""LangGraph 节点工厂与业务节点。

Worker 节点由 WorkerSpec 编译而成：节点内构建 Agent 并执行 ReAct 循环，
结构化产物经 ``bb_write_worker_output`` 投影为版本化条目。
"""
from uuid import uuid4

from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from langchain_core.runnables import RunnableConfig

from config import cfg
from graph.runtime import _summary_trigger_tokens, get_llm, parse_json_loose
from graph.state import AnalysisState
from tools.agent_tools import get_agent_tools
from tools.entry_tools import (
    bb_get_runtime,
    bb_log_event,
    bb_set_runtime,
    bb_write_worker_output,
)
from workers.specs import WorkerSpec


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
    及代入具体值后的前缀）和该角色适用的 subject_key 约定，full 模式 Agent 主动写入时
    才能与框架兜底投影使用同一公式、同一 subject_key。
    """
    project = state["sample_project_name"]
    export_dir = state.get("sample_export_dir", "")
    phase = _worker_phase(spec.name)
    key_prefix = f"{run_id}:{phase}:{spec.name}"
    from tools.entry_tools import _SAMPLE_FINDING_WORKERS

    if spec.name in _SAMPLE_FINDING_WORKERS:
        subject_guide = (
            'subject_key 约定: 样本条目的 subject_key 固定为 "sample"；'
            '每个发现条目的 subject_key 为 "{category}:{name}"'
            "（category 为 lowercase 类别名，如 string:http://evil.example/c2）。"
        )
    elif spec.name == "function_boundary_detector":
        subject_guide = (
            "subject_key 约定: 函数条目的 subject_key 为规范化汇编地址"
            "（0x 前缀 + 小写十六进制，如 0x401000；等价于 normalize_asm_address 的输出）。"
        )
    else:  # scheduler
        subject_guide = (
            'subject_key 约定: 决策条目的 subject_key 固定为 "phase2"；'
            "payload 中的函数地址会先规范化为 0x 小写十六进制地址，"
            "再经主题索引解析为函数条目的精确版本引用。"
        )
    return (
        f"分析样本: {project}, "
        f"导出目录: {export_dir}\n"
        f"本次运行 run_id: {run_id}，你的阶段: {phase}，worker 名: {spec.name}。\n"
        f"你的产物将由框架按幂等键公式写入黑板: "
        f"{{run_id}}:{{phase}}:{{worker_name}}:{{subject_key}}，"
        f"本次调用即 {key_prefix}:<subject_key>。{subject_guide}"
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
