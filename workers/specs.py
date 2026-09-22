"""WorkerSpec：worker 的框架无关定义（提示词 + 最小工具集 + 输出 schema）。

迁移自 ADK LlmAgent 定义；提示词常量逐字保留，工具面从 ALL_TOOLS 猴补丁
收敛为每个 worker 实际需要的 2-4 个。
"""
from dataclasses import dataclass
from typing import Callable, Optional

from langchain_core.tools import StructuredTool

from state import FunctionBoundaryAnalysis, StringAnalysis
from tools.blackboard_tools import bb_read_extract, bb_read_summary
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


string_artifact_analyst = WorkerSpec(
    name="string_artifact_analyst",
    instruction=STRING_ARTIFACT_ANALYST_INSTRUCTION,
    tools=(bb_read_extract, load_strings),
    output_key="string_analysis",
    output_schema=StringAnalysis,
)

api_behavior_profiler = WorkerSpec(
    name="api_behavior_profiler",
    instruction=API_BEHAVIOR_PROFILER_INSTRUCTION,
    tools=(bb_read_extract, load_imports, load_strings),
    output_key="api_behavior_analysis",
)

export_interface_analyzer = WorkerSpec(
    name="export_interface_analyzer",
    instruction=EXPORT_INTERFACE_ANALYZER_INSTRUCTION,
    tools=(bb_read_extract, load_exports, load_function_index),
    output_key="export_interface_analysis",
)

behavior_profile_synthesizer = WorkerSpec(
    name="behavior_profile_synthesizer",
    instruction=BEHAVIOR_PROFILE_SYNTHESIZER_INSTRUCTION,
    tools=(bb_read_summary,),
    output_key="behavior_profile",
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
)

# Phase 0 并行扇出 / Phase 1 并行扇出 / Phase 2 调度
PHASE0_SPECS = (string_artifact_analyst, api_behavior_profiler, export_interface_analyzer)
PHASE1_SPECS = (behavior_profile_synthesizer, function_boundary_detector)
ALL_SPECS = PHASE0_SPECS + PHASE1_SPECS + (scheduler,)
