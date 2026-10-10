"""StateGraph 组装：定义分析工作流的唯一位置（图拓扑如下）。

START → pre_extract → {string_analyst, api_profiler, export_analyzer}（并行扇出）
      → resolve_guides → {behavior_synth, function_boundary}（并行扇出）
      → scheduler → approval_gate → phase3_dispatch
      →（第一波 Send 扇出）phase3_topic(无依赖主题) / phase3_function(兜底函数)
      → phase3_wave2（中继：等第一波全部完成）
      →（第二波 Send 扇出）phase3_topic_dep(有依赖主题)
      → orchestrator（Phase 3 后置质量编排：docs 归档 + 质量/缺口/矛盾检查，纯代码）
      → verification_agent → shard_synthesis → aggregator → report_generator → END
"""
from langgraph.graph import END, START, StateGraph

from graph_nodes import (
    approval_gate_node,
    make_aggregator_node,
    make_phase3_function_node,
    make_report_generator_node,
    make_shard_synthesis_node,
    make_topic_node,
    make_worker_node,
    orchestrator_node,
    phase3_dispatch_node,
    phase3_fanout,
    phase3_fanout_wave2,
    phase3_wave2_node,
    pre_extract_node,
    resolve_guides_node,
)
from state import AnalysisState
from workers.specs import (
    PHASE0_SPECS,
    PHASE1_SPECS,
    scheduler,
    verification_agent,
)


def build_graph(llm=None, checkpointer=None):
    """构建并编译分析用的 StateGraph。

    Args:
        llm: 可选的 chat model 覆盖项（测试注入 fake 模型；None 表示按环境变量构造）。
        checkpointer: 可选的 LangGraph checkpointer（Step 2 接入持久化）。
    """
    builder = StateGraph(AnalysisState)

    # Phase -1：预提取
    builder.add_node("pre_extract", pre_extract_node)

    # Phase 0：快速定性（3 Worker 并行）
    for spec in PHASE0_SPECS:
        builder.add_node(spec.name, make_worker_node(spec, llm))

    # 知识路由
    builder.add_node("resolve_guides", resolve_guides_node)

    # Phase 1：行为定型 + 函数筛选（2 Worker 并行）
    for spec in PHASE1_SPECS:
        builder.add_node(spec.name, make_worker_node(spec, llm))

    # Phase 2：调度 + HITL 审批门
    builder.add_node(scheduler.name, make_worker_node(scheduler, llm))
    builder.add_node("approval_gate", approval_gate_node)

    # Phase 3：双轨制深度分析（批次 A2）
    # dispatch 构建 TaskManifest（主题任务 + 函数兜底 + 依赖分波）→ 条件边 Send 扇出；
    # wave0（无依赖主题 + 函数兜底）→ phase3_wave2 中继 → wave1（有依赖主题）；
    # 空任务时条件边直通 orchestrator
    builder.add_node("phase3_dispatch", phase3_dispatch_node)
    builder.add_node("phase3_topic", make_topic_node(llm))
    builder.add_node("phase3_function", make_phase3_function_node(llm))
    builder.add_node("phase3_wave2", phase3_wave2_node)
    builder.add_node("phase3_topic_dep", make_topic_node(llm))

    # Phase 3 后置：orchestrator 质量编排（纯代码节点：docs 归档 + 五要素质量检查 +
    # 缺口识别 meta/gap_report.json + 矛盾发现写 USER.md），两波 Phase 3 完成后执行
    builder.add_node("orchestrator", orchestrator_node)

    # Phase 3 后置：验证 Worker（回查 high 置信度发现的原始证据，WorkerSpec 编译）
    builder.add_node(verification_agent.name, make_worker_node(verification_agent, llm))

    # Phase 4：Map-Reduce 综合报告 + Markdown 综合参考手册
    builder.add_node("shard_synthesis", make_shard_synthesis_node(llm))
    builder.add_node("aggregator", make_aggregator_node(llm))
    builder.add_node("report_generator", make_report_generator_node(llm))

    # 边：一条边扇出即自动并行，多入边扇入（全部完成才继续）
    builder.add_edge(START, "pre_extract")
    for spec in PHASE0_SPECS:
        builder.add_edge("pre_extract", spec.name)
        builder.add_edge(spec.name, "resolve_guides")
    for spec in PHASE1_SPECS:
        builder.add_edge("resolve_guides", spec.name)
        builder.add_edge(spec.name, scheduler.name)
    builder.add_edge(scheduler.name, "approval_gate")
    builder.add_edge("approval_gate", "phase3_dispatch")
    builder.add_conditional_edges(
        "phase3_dispatch",
        phase3_fanout,
        ["phase3_topic", "phase3_function", "phase3_wave2", "orchestrator"],
    )
    # wave0 两条轨都扇入 wave2 中继（全部完成后才触发第二波）
    builder.add_edge("phase3_topic", "phase3_wave2")
    builder.add_edge("phase3_function", "phase3_wave2")
    builder.add_conditional_edges(
        "phase3_wave2", phase3_fanout_wave2, ["phase3_topic_dep", "orchestrator"]
    )
    # wave1 主题全部完成后扇入 orchestrator；orchestrator 完成后进入验证 Worker
    builder.add_edge("phase3_topic_dep", "orchestrator")
    builder.add_edge("orchestrator", verification_agent.name)
    builder.add_edge(verification_agent.name, "shard_synthesis")
    builder.add_edge("shard_synthesis", "aggregator")
    builder.add_edge("aggregator", "report_generator")
    builder.add_edge("report_generator", END)

    return builder.compile(checkpointer=checkpointer)
