import os
from dotenv import load_dotenv

from google.adk.agents import SequentialAgent, ParallelAgent, LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Import workers
from workers.phase0.string_artifact_analyst import string_artifact_analyst
from workers.phase0.api_behavior_profiler import api_behavior_profiler
from workers.phase0.export_interface_analyzer import export_interface_analyzer
from workers.phase1.behavior_profile_synthesizer import behavior_profile_synthesizer
from workers.phase1.function_boundary_detector import function_boundary_detector

# Import callbacks
from callbacks.human_review import human_review_callback

# Import tools for registration
from tools.file_loaders import (
    load_strings,
    load_exports,
    load_imports,
    load_function_index,
    load_pe_info,
    detect_sample_type,
)
from tools.pe_utils import calculate_entropy

# Load environment variables
load_dotenv()

# === Tool Registry ===
ALL_TOOLS = [
    load_strings,
    load_exports,
    load_imports,
    load_function_index,
    load_pe_info,
    detect_sample_type,
    calculate_entropy,
]

# Bind tools to workers
string_artifact_analyst.tools = ALL_TOOLS
api_behavior_profiler.tools = ALL_TOOLS
export_interface_analyzer.tools = ALL_TOOLS
behavior_profile_synthesizer.tools = ALL_TOOLS
function_boundary_detector.tools = ALL_TOOLS


def _get_or_create_parallel_agent(name, sub_agents):
    """Create a ParallelAgent, handling the case where sub-agents already have parents."""
    try:
        return ParallelAgent(name=name, sub_agents=sub_agents)
    except ValueError as e:
        if "already has a parent agent" in str(e):
            # Agents were already added in a previous import (e.g., pytest reload).
            # Return the existing parent from the first sub-agent.
            return sub_agents[0].parent_agent
        raise


# === Phase 0: Triage Swarm ===
phase0_triage_swarm = _get_or_create_parallel_agent(
    "phase0_triage_swarm",
    [string_artifact_analyst, api_behavior_profiler, export_interface_analyzer]
)

# === Phase 1: Deep Analysis Swarm ===
phase1_deep_swarm = _get_or_create_parallel_agent(
    "phase1_deep_swarm",
    [behavior_profile_synthesizer, function_boundary_detector]
)

# === Phase 2: Scheduler Agent ===
SCHEDULER_INSTRUCTION = """你是恶意样本分析系统的中央调度者。你不直接执行任何样本分析工作，你的职责是协调各个专业分析 Worker 的工作流，在关键决策点触发人工审查，并整合各 Worker 的分析结果。

【当前阶段】
Phase 0（快速定性）和 Phase 1（行为定型+函数筛选）已完成。5 个 Worker 的输出已写入 session.state：
- string_analysis: 字符串取证分析结果
- api_behavior_analysis: API 行为画像结果
- export_interface_analysis: 导出表与接口分析结果
- behavior_profile: 综合行为定型与架构推断
- function_boundary_analysis: 函数边界检测与候选函数排序

【你的任务】
1. 读取上述 5 个 Worker 的输出
2. 提取关键发现：
   - behavior_profile 中的行为定型结论（RAT/Stealer/Loader/Backdoor）
   - 各 Worker 中的 high severity 发现
   - function_boundary_analysis 中的 Top 20 候选函数
3. 生成简洁的状态报告，写入 output_key="scheduler_decision"
4. 更新 session.state["analysis_phase"] = "initial_complete"
5. after_agent_callback 将自动触发人工审查暂停

【输出格式】
输出严格 JSON 格式：
{
  "phase": "initial_complete",
  "action": "AWAITING_HUMAN_REVIEW",
  "summary": {
    "behavior_type": "定型结果",
    "confidence": "high|medium|low",
    "high_risk_count": 高风险发现数量,
    "candidate_functions": 候选函数数量
  },
  "details": {
    "string_key_findings": ["字符串关键发现"],
    "api_key_findings": ["API关键发现"],
    "export_key_findings": ["导出表关键发现"],
    "top_candidates": ["前5个候选函数信息"]
  }
}

【规则】
- 你只做数据路由和状态管理，不做任何样本分析推理
- 所有从 Worker 读取的数据必须通过 session.state 获取
- 不修改 Worker 的分析结果，只进行排序和筛选
"""

scheduler_agent = LlmAgent(
    name="scheduler",
    model="gemini-2.5-flash",
    description="Central scheduler that coordinates analysis workers and triggers human review.",
    instruction=SCHEDULER_INSTRUCTION,
    after_agent_callback=human_review_callback,
    output_key="scheduler_decision",
)

def _get_or_create_sequential_agent(name, sub_agents):
    """Create a SequentialAgent, handling the case where sub-agents already have parents."""
    try:
        return SequentialAgent(name=name, sub_agents=sub_agents)
    except ValueError as e:
        if "already has a parent agent" in str(e):
            # Agents were already added in a previous import.
            return sub_agents[0].parent_agent
        raise


# === Root Workflow ===
root_workflow = _get_or_create_sequential_agent(
    "malware_analysis_workflow",
    [phase0_triage_swarm, phase1_deep_swarm, scheduler_agent]
)


# === Runtime Entry ===
def run_analysis(
    sample_export_dir: str,
    sample_project_name: str,
    sample_type: str = "auto"
):
    """Run the complete malware sample analysis workflow.

    Args:
        sample_export_dir: Path to IDA no-MCP export directory.
        sample_project_name: Sample project name for tracking.
        sample_type: File type (pe/lnk/elf/auto).
    """

    session_service = InMemorySessionService()

    session = session_service.create_session(
        app_name="malware_analysis",
        user_id="analyst_001",
        session_id=f"analysis_{sample_project_name}",
        state={
            "sample_project_name": sample_project_name,
            "sample_export_dir": sample_export_dir,
            "sample_type": sample_type,
            "analysis_phase": "initial",
            "execution_status": "RUNNING",
        }
    )

    runner = Runner(
        agent=root_workflow,
        app_name="malware_analysis",
        session_service=session_service
    )

    content = types.Content(
        role="user",
        parts=[types.Part(
            text=f"分析样本: {sample_project_name}, 导出目录: {sample_export_dir}"
        )]
    )

    events = []
    for event in runner.run(
        user_id="analyst_001",
        session_id=session.id,
        new_message=content
    ):
        events.append(event)
        if event.is_final_response():
            print(f"完成: {event.content.parts[0].text}")

    return runner, session_service, events


# Backward compatibility: expose root_agent for ADK CLI
root_agent = root_workflow
