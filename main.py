"""运行时入口：构建 LangGraph 图并执行分析。

替代原 agent.py（ADK Runner + setup_fn HITL）。配置改为通过 CLI 参数 / 环境变量收集，
不再使用 RequestInput 文本协议。HITL 审批门由图内 interrupt() 挂起，本模块负责
展示 interrupt 负载并读取人工回复恢复执行（图状态由 checkpointer 持久化）。
"""
import argparse
import asyncio
import contextlib
import os
from typing import Optional

from dotenv import load_dotenv
from langgraph.types import Command

load_dotenv()


def resolve_sample_export_dir(
    sample_project_name: str,
    input_name: Optional[str] = None,
    sample_export_dir: Optional[str] = None,
) -> str:
    """解析 IDA 导出目录（显式 export_dir > data/input/ 自动发现），失败抛 RuntimeError。

    供 CLI 与 Web UI 共用的入口参数解析。
    """
    from tools.file_loaders import resolve_export_dir

    if sample_export_dir is not None:
        return sample_export_dir
    resolved = resolve_export_dir(
        project_name=sample_project_name, input_name=input_name
    )
    if resolved["status"] != "success":
        raise RuntimeError(
            f"{resolved['error']}（候选: {resolved['candidates']}）"
        )
    return resolved["export_dir"]


def make_saver_cm(project_name: str, checkpointer=None):
    """为项目创建 checkpointer 的异步上下文管理器。

    外部注入 checkpointer 时原样包装（不接管其生命周期）；缺省时按项目黑板目录
    创建 AsyncSqliteSaver，数据库落在 data/output/{project}/checkpoints.db
    （interrupt 恢复与服务重启后的审批现场恢复都依赖它）。
    """
    from tools.blackboard_tools import board_path

    if checkpointer is not None:
        return contextlib.async_nullcontext(checkpointer)
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    os.makedirs(board_path(project_name), exist_ok=True)
    return AsyncSqliteSaver.from_conn_string(
        board_path(project_name, "checkpoints.db")
    )


def collect_pending_interrupts(snapshot) -> list:
    """从 aget_state 快照收集所有挂起的 interrupt（空列表表示无挂起）。

    供 CLI 中断循环与 Web UI 状态查询共用的中断检测。
    """
    return [it for task in snapshot.tasks for it in task.interrupts]


async def run_analysis_with_blackboard(
    sample_project_name: str,
    input_name: Optional[str] = None,
    sample_export_dir: Optional[str] = None,
    resume: bool = False,
    checkpointer=None,
    focus: Optional[str] = None,
    exclude: Optional[str] = None,
):
    """运行带 blackboard（黑板）上下文管理的完整分析工作流。

    Args:
        sample_project_name: 样本项目名（data/output/ 下的子目录名）。
        input_name: 可选的 data/input/ 导出目录名（可带或不带 _export_for_ai 后缀）；
            省略时自动解析。
        sample_export_dir: 显式指定的 IDA 导出目录；给出时绕过 data/input/ 自动发现。
        resume: 为 True 且已存在 checkpoint 时跳过 Phase -1（黑板层断点，
            与图级 checkpointer 互补）。
        checkpointer: 可选的 LangGraph checkpointer；缺省时为本次运行创建
            AsyncSqliteSaver，数据库文件落在黑板目录 checkpoints.db。
        focus: C2 用户重点关注领域（逗号分隔原文，如 "驻留,持久化"）；写入图状态
            user_focus 并由 pre_extract 落盘 USER.md，各 prompt 注入点优先详写。
        exclude: C2 用户排除领域（不深入静态分析过程，只保留动调提取方案）；
            写入图状态 user_exclude，链路同 focus。

    Returns:
        (final_state, token_report) 元组。
    """
    from graph import build_graph
    from observability import TokenStatsCallback, register_callback

    sample_export_dir = resolve_sample_export_dir(
        sample_project_name, input_name=input_name, sample_export_dir=sample_export_dir
    )

    async with make_saver_cm(sample_project_name, checkpointer) as saver:
        graph = build_graph(checkpointer=saver)
        graph.get_graph().draw_mermaid_png(output_file_path="data/graph.png")
        token_callback = TokenStatsCallback(sample_project_name)
        # 注册到模块级注册表：token 预算闸门（invoke_guarded / worker 入口）据此查实时用量
        register_callback(sample_project_name, token_callback)

        initial_state = {
            "sample_project_name": sample_project_name,
            "sample_export_dir": sample_export_dir,
            "resume": resume,
        }
        # C2 用户分析优先级：有值才进图状态（缺省零行为变化）
        if focus:
            initial_state["user_focus"] = focus
        if exclude:
            initial_state["user_exclude"] = exclude
        config = {
            "configurable": {"thread_id": sample_project_name},
            "callbacks": [token_callback],
        }

        final_state = await graph.ainvoke(initial_state, config=config)
        # HITL 中断处理循环：审批门挂起时展示 interrupt 负载，读取人工回复后恢复
        while True:
            snapshot = await graph.aget_state(config)
            pending = collect_pending_interrupts(snapshot)
            if not pending:
                break
            for intr in pending:
                payload = intr.value if isinstance(intr.value, dict) else {"message": intr.value}
                if payload.get("error"):
                    print(f"[ERROR] {payload['error']}")
                print(payload.get("message", payload))
                reply = input("请回复 CONFIRM 或 MODIFY <addr1>,<addr2>,...: ")
                final_state = await graph.ainvoke(Command(resume=reply), config=config)

    print(str(token_callback.report))
    return final_state, token_callback.report


def main() -> None:
    from config import cfg, cfg_bool

    # 默认值来源：config.yaml > 环境变量；CLI 显式传参始终优先
    default_project = cfg("analysis.project_name", env="PROJECT_NAME")
    default_input = cfg("analysis.input_name", env="INPUT_NAME")
    default_resume = cfg_bool("analysis.resume", env="RESUME", default=False)
    default_focus = cfg("analysis.focus", env="FOCUS")
    default_exclude = cfg("analysis.exclude", env="EXCLUDE")

    parser = argparse.ArgumentParser(
        description="RevAgent 恶意样本静态分析系统（LangGraph）。"
        "自动分析 data/input/ 下的 *_export_for_ai 目录，结果写入 data/output/<project-name>/。"
        "默认参数读取根目录 config.yaml，CLI 传参优先。"
    )
    parser.add_argument(
        "-p",
        "--project-name",
        default=default_project,
        required=default_project is None,
        help="项目存档名（data/output/ 子目录名；默认取 config.yaml analysis.project_name）",
    )
    parser.add_argument(
        "-i",
        "--input-name",
        default=default_input,
        help="data/input/ 下的导出目录名（可省略 _export_for_ai 后缀；"
        "默认取 config.yaml analysis.input_name，缺省按 project-name 前缀或唯一候选自动匹配）",
    )
    parser.add_argument(
        "-r",
        "--resume",
        action="store_true",
        default=default_resume,
        help="从黑板 checkpoint 断点续跑（默认取 config.yaml analysis.resume）",
    )
    parser.add_argument(
        "--focus",
        default=default_focus,
        help="用户重点关注的分析领域，逗号分隔（如 \"驻留,持久化,窃取\"）；"
        "对应维度优先详细展开（默认取 config.yaml analysis.focus，环境变量 FOCUS 兜底）",
    )
    parser.add_argument(
        "--exclude",
        default=default_exclude,
        help="用户指示不深入分析的领域，逗号分隔（如 \"加解密过程\"）；"
        "对应维度只保留动态调试提取方案，不展开静态过程"
        "（默认取 config.yaml analysis.exclude，环境变量 EXCLUDE 兜底）",
    )
    args = parser.parse_args()

    asyncio.run(
        run_analysis_with_blackboard(
            sample_project_name=args.project_name,
            input_name=args.input_name,
            resume=args.resume,
            focus=args.focus,
            exclude=args.exclude,
        )
    )


if __name__ == "__main__":
    main()
