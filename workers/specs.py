"""WorkerSpec：worker 的框架无关定义（提示词 + 统一 WorkerOutput schema）。

Worker 不再有独立工具集声明：节点由 graph.workers.make_worker_node 编译时
通过 tools.agent_tools.get_agent_tools(spec.name, ...) 按角色动态注入工具；
产物统一为 tools.entry_models.WorkerOutput，由 bb_write_worker_output 投影为版本化条目。
"""
from dataclasses import dataclass

from tools.entry_models import WorkerOutput
from workers.phase0.api_behavior_profiler import API_BEHAVIOR_PROFILER_INSTRUCTION
from workers.phase0.export_interface_analyzer import EXPORT_INTERFACE_ANALYZER_INSTRUCTION
from workers.phase0.string_artifact_analyst import STRING_ARTIFACT_ANALYST_INSTRUCTION
from workers.phase1.behavior_profile_synthesizer import BEHAVIOR_PROFILE_SYNTHESIZER_INSTRUCTION
from workers.phase1.function_boundary_detector import FUNCTION_BOUNDARY_DETECTOR_INSTRUCTION
from workers.phase2.scheduler import SCHEDULER_INSTRUCTION


@dataclass(frozen=True)
class WorkerSpec:
    """Worker 的纯数据定义：由 graph.workers.make_worker_node 编译为图节点。"""

    name: str
    instruction: str  # 复用现有五段式提示词
    output_schema: type = WorkerOutput  # 六个 spec 统一使用 WorkerOutput


string_artifact_analyst = WorkerSpec(
    name="string_artifact_analyst",
    instruction=STRING_ARTIFACT_ANALYST_INSTRUCTION,
)

api_behavior_profiler = WorkerSpec(
    name="api_behavior_profiler",
    instruction=API_BEHAVIOR_PROFILER_INSTRUCTION,
)

export_interface_analyzer = WorkerSpec(
    name="export_interface_analyzer",
    instruction=EXPORT_INTERFACE_ANALYZER_INSTRUCTION,
)

behavior_profile_synthesizer = WorkerSpec(
    name="behavior_profile_synthesizer",
    instruction=BEHAVIOR_PROFILE_SYNTHESIZER_INSTRUCTION,
)

function_boundary_detector = WorkerSpec(
    name="function_boundary_detector",
    instruction=FUNCTION_BOUNDARY_DETECTOR_INSTRUCTION,
)

scheduler = WorkerSpec(
    name="scheduler",
    instruction=SCHEDULER_INSTRUCTION,
)

# Phase 0 并行扇出 / Phase 1 并行扇出 / Phase 2 调度
PHASE0_SPECS = (string_artifact_analyst, api_behavior_profiler, export_interface_analyzer)
PHASE1_SPECS = (behavior_profile_synthesizer, function_boundary_detector)
ALL_SPECS = PHASE0_SPECS + PHASE1_SPECS + (scheduler,)
