"""Runtime entry: build the LangGraph graph and run the analysis.

Replaces agent.py (ADK Runner + setup_fn HITL). Configuration is collected
via CLI args / env vars instead of a RequestInput text protocol.
"""
import argparse
import asyncio
import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


async def run_analysis_with_blackboard(
    sample_project_name: str,
    input_name: Optional[str] = None,
    sample_export_dir: Optional[str] = None,
    resume: bool = False,
):
    """Run the complete analysis workflow with blackboard context management.

    Args:
        sample_project_name: Sample project name (data/output/ subdirectory).
        input_name: Optional export dir name under data/input/ (with or without
            the _export_for_ai suffix). Resolved automatically when omitted.
        sample_export_dir: Explicit IDA export directory; bypasses data/input/
            auto-discovery when given.
        resume: If True, skip Phase -1 when a checkpoint already exists.

    Returns:
        Tuple of (final_state, token_report)
    """
    from graph import build_graph
    from observability import TokenStatsCallback
    from tools.file_loaders import resolve_export_dir

    if sample_export_dir is None:
        resolved = resolve_export_dir(
            project_name=sample_project_name, input_name=input_name
        )
        if resolved["status"] != "success":
            raise RuntimeError(
                f"{resolved['error']}（候选: {resolved['candidates']}）"
            )
        sample_export_dir = resolved["export_dir"]

    graph = build_graph()
    token_callback = TokenStatsCallback(sample_project_name)

    initial_state = {
        "sample_project_name": sample_project_name,
        "sample_export_dir": sample_export_dir,
        "resume": resume,
    }

    final_state = await graph.ainvoke(
        initial_state,
        config={"callbacks": [token_callback]},
    )

    print(str(token_callback.report))
    return final_state, token_callback.report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RevAgent 恶意样本静态分析系统（LangGraph）。"
        "自动分析 data/input/ 下的 *_export_for_ai 目录，结果写入 data/output/<project-name>/。"
    )
    parser.add_argument(
        "-p",
        "--project-name",
        default=os.getenv("PROJECT_NAME"),
        required=os.getenv("PROJECT_NAME") is None,
        help="项目存档名（data/output/ 子目录名）",
    )
    parser.add_argument(
        "-i",
        "--input-name",
        default=os.getenv("INPUT_NAME"),
        help="data/input/ 下的导出目录名（可省略 _export_for_ai 后缀；"
        "默认按 project-name 前缀或唯一候选自动匹配）",
    )
    parser.add_argument(
        "-r",
        "--resume",
        action="store_true",
        help="从黑板 checkpoint 断点续跑",
    )
    args = parser.parse_args()

    asyncio.run(
        run_analysis_with_blackboard(
            sample_project_name=args.project_name,
            input_name=args.input_name,
            resume=args.resume,
        )
    )


if __name__ == "__main__":
    main()
