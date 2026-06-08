import os
import sys

# Ensure project root is in Python path for ADK CLI imports
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from dotenv import load_dotenv

from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.workflow._base_node import START
from google.adk.workflow._workflow import Workflow
from google.genai import types
from google.adk.models.lite_llm import LiteLlm

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

# === LiteLLM Model Configuration ===
_raw_model = os.getenv("MOONSHOT_MODEL", "openai/kimi-k2.5")
# Ensure openai/ prefix for LiteLlm to route to OpenAI-compatible API
if "/" not in _raw_model:
    _raw_model = f"openai/{_raw_model}"

LLM_MODEL = LiteLlm(
    model=_raw_model,
    api_key=os.getenv("MOONSHOT_API_KEY"),
    api_base=os.getenv("MOONSHOT_BASE_URL", "https://api.moonshot.cn/v1"),
)

scheduler_agent = LlmAgent(
    name="scheduler",
    model=LLM_MODEL,
    description="Central scheduler that coordinates analysis workers and triggers human review.",
    instruction=SCHEDULER_INSTRUCTION,
    after_agent_callback=human_review_callback,
    output_key="scheduler_decision",
)

# Override model for all workers
string_artifact_analyst.model = LLM_MODEL
api_behavior_profiler.model = LLM_MODEL
export_interface_analyzer.model = LLM_MODEL
behavior_profile_synthesizer.model = LLM_MODEL
function_boundary_detector.model = LLM_MODEL

# === Root Workflow (using Workflow instead of deprecated ParallelAgent/SequentialAgent) ===
root_workflow = Workflow(
    name="malware_analysis_workflow",
    edges=[
        # Phase 0: Triage — 3 workers run in parallel
        (START, (string_artifact_analyst, api_behavior_profiler, export_interface_analyzer)),
        # Phase 1: Deep Analysis — 2 workers run in parallel after Phase 0 completes
        ((string_artifact_analyst, api_behavior_profiler, export_interface_analyzer),
         (behavior_profile_synthesizer, function_boundary_detector)),
        # Phase 2: Scheduler runs after Phase 1 completes
        ((behavior_profile_synthesizer, function_boundary_detector), scheduler_agent),
    ]
)


# === Token Statistics Collector ===

@dataclass
class StageTokenStats:
    """Token usage stats for a single stage/node."""
    stage_name: str
    prompt_tokens: int = 0
    candidate_tokens: int = 0
    total_tokens: int = 0
    call_count: int = 0

    def add_usage(self, usage_metadata: Optional[Any]) -> None:
        """Add usage metadata from a single LLM call."""
        if usage_metadata is None:
            return
        self.prompt_tokens += getattr(usage_metadata, 'promptTokenCount', 0) or 0
        self.candidate_tokens += getattr(usage_metadata, 'candidatesTokenCount', 0) or 0
        self.total_tokens += getattr(usage_metadata, 'totalTokenCount', 0) or 0
        self.call_count += 1


@dataclass
class AnalysisTokenReport:
    """Complete token usage report for an analysis session."""
    sample_project_name: str
    stages: Dict[str, StageTokenStats] = field(default_factory=dict)
    total_prompt_tokens: int = 0
    total_candidate_tokens: int = 0
    total_tokens: int = 0
    total_llm_calls: int = 0

    def add_event_usage(self, event) -> None:
        """Process an ADK Event and extract token usage."""
        if not hasattr(event, 'usageMetadata') or event.usageMetadata is None:
            return

        # Determine stage from event node info
        stage_name = "unknown"
        if hasattr(event, 'nodeInfo') and event.nodeInfo:
            stage_name = event.nodeInfo.node_name or "unknown"

        if stage_name not in self.stages:
            self.stages[stage_name] = StageTokenStats(stage_name=stage_name)

        self.stages[stage_name].add_usage(event.usageMetadata)

        # Update totals
        self.total_prompt_tokens += getattr(event.usageMetadata, 'promptTokenCount', 0) or 0
        self.total_candidate_tokens += getattr(event.usageMetadata, 'candidatesTokenCount', 0) or 0
        self.total_tokens += getattr(event.usageMetadata, 'totalTokenCount', 0) or 0
        self.total_llm_calls += 1

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to dict."""
        return {
            "sample_project_name": self.sample_project_name,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_candidate_tokens": self.total_candidate_tokens,
            "total_tokens": self.total_tokens,
            "total_llm_calls": self.total_llm_calls,
            "stages": {
                name: {
                    "stage_name": s.stage_name,
                    "prompt_tokens": s.prompt_tokens,
                    "candidate_tokens": s.candidate_tokens,
                    "total_tokens": s.total_tokens,
                    "call_count": s.call_count,
                }
                for name, s in self.stages.items()
            },
        }

    def __str__(self) -> str:
        """Human-readable summary."""
        lines = [
            f"=== Token Usage Report: {self.sample_project_name} ===",
            f"Total LLM Calls: {self.total_llm_calls}",
            f"Total Prompt Tokens: {self.total_prompt_tokens:,}",
            f"Total Candidate Tokens: {self.total_candidate_tokens:,}",
            f"Total Tokens: {self.total_tokens:,}",
            "",
            "--- Per-Stage Breakdown ---",
        ]
        for name, stats in sorted(self.stages.items(), key=lambda x: -x[1].total_tokens):
            lines.append(
                f"  {stats.stage_name}: "
                f"{stats.call_count} calls, "
                f"{stats.total_tokens:,} tokens "
                f"(prompt: {stats.prompt_tokens:,}, candidate: {stats.candidate_tokens:,})"
            )
        lines.append("")
        return "\n".join(lines)


# === Runtime Entry ===
def run_analysis(
    sample_export_dir: str,
    sample_project_name: str,
    sample_type: str = "auto"
) -> tuple:
    """Run the complete malware sample analysis workflow.

    Args:
        sample_export_dir: Path to IDA no-MCP export directory.
        sample_project_name: Sample project name for tracking.
        sample_type: File type (pe/lnk/elf/auto).

    Returns:
        Tuple of (runner, session_service, events, token_report)
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

    # Collect events and token usage
    token_report = AnalysisTokenReport(sample_project_name=sample_project_name)
    events = []

    for event in runner.run(
        user_id="analyst_001",
        session_id=session.id,
        new_message=content
    ):
        events.append(event)

        # Extract token usage from event
        token_report.add_event_usage(event)

        if event.is_final_response():
            print(f"完成: {event.content.parts[0].text}")

    # Print token report
    print(str(token_report))

    return runner, session_service, events, token_report


# Backward compatibility: expose root_agent for ADK CLI
root_agent = root_workflow
