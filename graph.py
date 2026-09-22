"""StateGraph assembly: the single place defining the analysis workflow.

START → pre_extract → {string_analyst, api_profiler, export_analyzer} (并行扇出)
      → resolve_guides → {behavior_synth, function_boundary} (并行扇出)
      → scheduler → approval_gate → phase3_deep_analysis
      → shard_synthesis → aggregator → END
"""
from langgraph.graph import END, START, StateGraph

from graph_nodes import (
    approval_gate_node,
    make_aggregator_node,
    make_phase3_node,
    make_shard_synthesis_node,
    make_worker_node,
    pre_extract_node,
    resolve_guides_node,
)
from state import AnalysisState
from workers.specs import (
    PHASE0_SPECS,
    PHASE1_SPECS,
    scheduler,
)


def build_graph(llm=None, checkpointer=None):
    """Build and compile the analysis StateGraph.

    Args:
        llm: Optional chat model override (tests inject fakes; None = env-based).
        checkpointer: Optional LangGraph checkpointer (Step 2 接入持久化).
    """
    builder = StateGraph(AnalysisState)

    # Phase -1
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

    # Phase 3：函数级深度分析
    builder.add_node("phase3_deep_analysis", make_phase3_node(llm))

    # Phase 4：Map-Reduce 综合报告
    builder.add_node("shard_synthesis", make_shard_synthesis_node(llm))
    builder.add_node("aggregator", make_aggregator_node(llm))

    # 边：一条边扇出即自动并行，多入边扇入（全部完成才继续）
    builder.add_edge(START, "pre_extract")
    for spec in PHASE0_SPECS:
        builder.add_edge("pre_extract", spec.name)
        builder.add_edge(spec.name, "resolve_guides")
    for spec in PHASE1_SPECS:
        builder.add_edge("resolve_guides", spec.name)
        builder.add_edge(spec.name, scheduler.name)
    builder.add_edge(scheduler.name, "approval_gate")
    builder.add_edge("approval_gate", "phase3_deep_analysis")
    builder.add_edge("phase3_deep_analysis", "shard_synthesis")
    builder.add_edge("shard_synthesis", "aggregator")
    builder.add_edge("aggregator", END)

    return builder.compile(checkpointer=checkpointer)
