"""WorkerSpec：worker 的框架无关定义（提示词 + 最小工具集 + 输出 schema）。

迁移自 ADK LlmAgent 定义；提示词常量逐字保留，工具面从 ALL_TOOLS 猴补丁
收敛为每个 worker 实际需要的 2-4 个。
"""
from dataclasses import dataclass
from typing import Callable, Optional

from langchain_core.tools import StructuredTool

from state import (
    ApiBehaviorAnalysis,
    BehaviorProfile,
    ExportInterfaceAnalysis,
    FunctionBoundaryAnalysis,
    SchedulerDecision,
    StringAnalysis,
    VerificationReport,
)
from tools.blackboard_tools import (
    bb_list_artifacts,
    bb_read_artifact,
    bb_read_extract,
    bb_read_summary,
)
from tools.file_loaders import (
    load_exports,
    load_function_index,
    load_imports,
    load_strings,
)
from workers.knowledge import load_knowledge
from workers.phase0.api_behavior_profiler import API_BEHAVIOR_PROFILER_INSTRUCTION
from workers.phase0.export_interface_analyzer import EXPORT_INTERFACE_ANALYZER_INSTRUCTION
from workers.phase0.string_artifact_analyst import STRING_ARTIFACT_ANALYST_INSTRUCTION
from workers.phase1.behavior_profile_synthesizer import BEHAVIOR_PROFILE_SYNTHESIZER_INSTRUCTION
from workers.phase1.function_boundary_detector import FUNCTION_BOUNDARY_DETECTOR_INSTRUCTION
from workers.phase2.scheduler import SCHEDULER_INSTRUCTION
from workers.phase3.verification_agent import VERIFICATION_AGENT_INSTRUCTION

# 提示词中要求模型调用 load_arch_guide("__active__")，
# langchain 默认以函数 __name__ 作为工具名，这里显式命名保持一致。
load_arch_guide = StructuredTool.from_function(
    load_knowledge,
    name="load_arch_guide",
    description=load_knowledge.__doc__,
)


@dataclass(frozen=True)
class WorkerSpec:
    """Worker 的纯数据定义：由 graph_nodes.make_worker_node 编译为图节点。"""

    name: str
    instruction: str  # 复用现有五段式提示词
    tools: tuple  # 最小工具集，定义处显式声明
    output_key: str  # 写入 State 的键
    output_schema: Optional[type] = None
    # 模型分层（B1）："light"=轻任务小模型（llm.light_* 配置，缺省回退主模型）；
    # "strong"=主模型。轻任务 = triage/调度/验证这类摘要级工作。
    tier: str = "strong"


string_artifact_analyst = WorkerSpec(
    name="string_artifact_analyst",
    instruction=STRING_ARTIFACT_ANALYST_INSTRUCTION,
    tools=(bb_read_extract, load_strings),
    output_key="string_analysis",
    output_schema=StringAnalysis,
    tier="light",
)

api_behavior_profiler = WorkerSpec(
    name="api_behavior_profiler",
    instruction=API_BEHAVIOR_PROFILER_INSTRUCTION,
    tools=(bb_read_extract, load_imports, load_strings),
    output_key="api_behavior_analysis",
    output_schema=ApiBehaviorAnalysis,
    tier="light",
)

export_interface_analyzer = WorkerSpec(
    name="export_interface_analyzer",
    instruction=EXPORT_INTERFACE_ANALYZER_INSTRUCTION,
    tools=(bb_read_extract, load_exports, load_function_index),
    output_key="export_interface_analysis",
    output_schema=ExportInterfaceAnalysis,
    tier="light",
)

behavior_profile_synthesizer = WorkerSpec(
    name="behavior_profile_synthesizer",
    instruction=BEHAVIOR_PROFILE_SYNTHESIZER_INSTRUCTION,
    tools=(bb_read_summary,),
    output_key="behavior_profile",
    output_schema=BehaviorProfile,
)

function_boundary_detector = WorkerSpec(
    name="function_boundary_detector",
    instruction=FUNCTION_BOUNDARY_DETECTOR_INSTRUCTION,
    tools=(bb_read_extract, load_function_index, load_exports, load_arch_guide),
    output_key="function_boundary_analysis",
    output_schema=FunctionBoundaryAnalysis,
)

scheduler = WorkerSpec(
    name="scheduler",
    instruction=SCHEDULER_INSTRUCTION,
    tools=(bb_read_summary,),
    output_key="scheduler_decision",
    output_schema=SchedulerDecision,
    tier="light",
)

# Phase 3 后置验证 Worker：回查 high 置信度发现的原始 artifact 证据（反幻觉）。
# p0/p1 artifact 名带时间戳无法猜测，故工具集含 bb_list_artifacts 用于按前缀定位。
verification_agent = WorkerSpec(
    name="verification_agent",
    instruction=VERIFICATION_AGENT_INSTRUCTION,
    tools=(bb_read_summary, bb_read_artifact, bb_list_artifacts),
    output_key="verification_report",
    output_schema=VerificationReport,
    tier="light",
)

# Phase 0 并行扇出 / Phase 1 并行扇出 / Phase 2 调度 / Phase 3 后置验证
PHASE0_SPECS = (string_artifact_analyst, api_behavior_profiler, export_interface_analyzer)
PHASE1_SPECS = (behavior_profile_synthesizer, function_boundary_detector)
ALL_SPECS = PHASE0_SPECS + PHASE1_SPECS + (scheduler, verification_agent)
