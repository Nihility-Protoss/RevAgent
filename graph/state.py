"""LangGraph 状态定义：收缩版 AnalysisState（控制字段 + 条目黑板引用）。"""
from typing import TypedDict


# ---- 图状态：只保留控制字段，所有分析产物经条目黑板（versioned entries）通信 ----
class AnalysisState(TypedDict, total=False):
    """LangGraph 图状态：仅承载运行控制字段，不再携带任何 worker payload。

    各阶段的分析产物全部写入条目黑板（``data/output/{project}/entries/``），
    节点之间通过 ``bb_build_context`` / ``bb_query_entries`` 按需读取；
    Phase 4 的 reduce 节点只把最终报告的条目 id 写回 ``final_report_entry_id``。
    """

    # 初始化参数
    sample_project_name: str
    sample_export_dir: str
    sample_type: str
    resume: bool  # True 时跳过 Phase -1 预提取（黑板已有 checkpoint）
    # 运行标识与最终产物引用
    run_id: str  # 由 pre_extract 节点生成并持久化到黑板 runtime
    final_report_entry_id: str  # Phase 4 reduce 节点写入的最终报告条目 id
