"""Token usage statistics collection for analysis runs."""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


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
