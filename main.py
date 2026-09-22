"""Runtime entry: build the LangGraph graph and run the analysis.

Replaces agent.py (ADK Runner + setup_fn HITL). Configuration is collected
via CLI args / env vars instead of a RequestInput text protocol.
"""
import argparse
import asyncio
import os

from dotenv import load_dotenv

load_dotenv()


async def run_analysis_with_blackboard(
    sample_export_dir: str,
    sample_project_name: str,
    sample_type: str = "auto",
    resume: bool = False,
):
    """Run the complete analysis workflow with blackboard context management.

    Args:
        sample_export_dir: Path to IDA export directory.
        sample_project_name: Sample project name (blackboard subdirectory).
        sample_type: File type (pe/lnk/elf/auto).
        resume: If True, skip Phase -1 when a checkpoint already exists.

    Returns:
        Tuple of (final_state, token_report)
    """
    from graph import build_graph
    from observability import TokenStatsCallback

    graph = build_graph()
    token_callback = TokenStatsCallback(sample_project_name)

    initial_state = {
        "sample_project_name": sample_project_name,
        "sample_export_dir": sample_export_dir,
        "sample_type": sample_type,
        "resume": resume,
    }

    final_state = await graph.ainvoke(
        initial_state,
        config={"callbacks": [token_callback]},
    )

    print(str(token_callback.report))
    return final_state, token_callback.report


def main() -> None:
    parser = argparse.ArgumentParser(description="RevAgent 恶意样本静态分析系统（LangGraph）")
    parser.add_argument(
        "--export-dir",
        default=os.getenv("EXPORT_DIR"),
        required=os.getenv("EXPORT_DIR") is None,
        help="IDA 导出目录（含 strings.txt/imports.txt/exports.txt/function_index.txt）",
    )
    parser.add_argument(
        "--project-name",
        default=os.getenv("PROJECT_NAME"),
        required=os.getenv("PROJECT_NAME") is None,
        help="项目存档名（.blackboard/ 子目录名）",
    )
    parser.add_argument(
        "--work-dir",
        default=os.getenv("WORK_DIR", "."),
        help="工作目录（.blackboard/ 存放位置，默认当前目录）",
    )
    parser.add_argument("--sample-type", default="auto", help="样本类型 (pe/lnk/elf/auto)")
    parser.add_argument("--resume", action="store_true", help="从黑板 checkpoint 断点续跑")
    args = parser.parse_args()

    if not os.path.isdir(args.export_dir):
        raise SystemExit(f"EXPORT_DIR 不存在或不是目录: {args.export_dir}")

    if args.work_dir != ".":
        os.makedirs(args.work_dir, exist_ok=True)
        os.chdir(args.work_dir)

    asyncio.run(
        run_analysis_with_blackboard(
            sample_export_dir=args.export_dir,
            sample_project_name=args.project_name,
            sample_type=args.sample_type,
            resume=args.resume,
        )
    )


if __name__ == "__main__":
    main()
