"""运行时入口：构建 LangGraph 图并执行分析。

替代原 agent.py（ADK Runner + setup_fn HITL）。配置全部来自根目录 config.yaml
（环境变量仅作回退），不再提供 CLI 参数：改完配置直接 `python main.py` 即可。
"""
import asyncio
from typing import Optional

from dotenv import load_dotenv

import graph  # 模块级导入：便于测试 monkeypatch graph.build_graph
from tools.entry_store import shutdown_stores

load_dotenv()


async def run_analysis_with_blackboard(
    sample_project_name: str,
    input_name: Optional[str] = None,
    sample_export_dir: Optional[str] = None,
    resume: bool = False,
):
    """运行带 blackboard（黑板）上下文管理的完整分析工作流。

    Args:
        sample_project_name: 样本项目名（data/output/ 下的子目录名）。
        input_name: 可选的 data/input/ 导出目录名（可带或不带 _export_for_ai 后缀）；
            省略时自动解析。
        sample_export_dir: 显式指定的 IDA 导出目录；给出时绕过 data/input/ 自动发现。
        resume: 为 True 且已存在 checkpoint 时跳过 Phase -1。

    Returns:
        (final_state, token_report) 元组。
    """
    from graph.observability import TokenStatsCallback
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

    app = graph.build_graph()
    app.get_graph().draw_mermaid_png(output_file_path="data/graph.png")
    token_callback = TokenStatsCallback(sample_project_name)

    initial_state = {
        "sample_project_name": sample_project_name,
        "sample_export_dir": sample_export_dir,
        "resume": resume,
    }

    try:
        final_state = await app.ainvoke(
            initial_state,
            config={"callbacks": [token_callback]},
        )
        print(str(token_callback.report))
        return final_state, token_callback.report
    finally:
        # 即使 LLM 或 HITL 异常也强制落盘脏数据，避免条目丢失
        shutdown_stores()


def main() -> None:
    from config import cfg, cfg_bool

    # 配置来源：config.yaml > 环境变量；无 CLI 覆盖
    project_name = cfg("analysis.project_name", env="PROJECT_NAME")
    if not project_name:
        raise RuntimeError(
            "未配置分析项目名：请在根目录 config.yaml 的 analysis.project_name 中配置"
            "（data/output/ 下的存档名），或设置 PROJECT_NAME 环境变量。"
        )
    input_name = cfg("analysis.input_name", env="INPUT_NAME")
    resume = cfg_bool("analysis.resume", env="RESUME", default=False)

    asyncio.run(
        run_analysis_with_blackboard(
            sample_project_name=project_name,
            input_name=input_name,
            resume=resume,
        )
    )


if __name__ == "__main__":
    main()
