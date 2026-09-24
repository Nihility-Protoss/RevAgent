"""分析运行的 token 用量统计收集。"""
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class StageTokenStats:
    """单个阶段/节点的 token 用量统计。"""
    stage_name: str
    prompt_tokens: int = 0
    candidate_tokens: int = 0
    total_tokens: int = 0
    call_count: int = 0

    def add_usage(self, prompt_tokens: int, candidate_tokens: int, total_tokens: int) -> None:
        """累加一次 LLM 调用的 token 用量。"""
        self.prompt_tokens += prompt_tokens
        self.candidate_tokens += candidate_tokens
        self.total_tokens += total_tokens
        self.call_count += 1


@dataclass
class AnalysisTokenReport:
    """一次分析会话的完整 token 用量报告。"""
    sample_project_name: str
    stages: Dict[str, StageTokenStats] = field(default_factory=dict)
    total_prompt_tokens: int = 0
    total_candidate_tokens: int = 0
    total_tokens: int = 0
    total_llm_calls: int = 0

    def add_usage(self, stage_name: str, prompt_tokens: int, candidate_tokens: int, total_tokens: int) -> None:
        """把一次 LLM 调用的 token 用量归集到指定的阶段/节点名下。"""
        stage_name = stage_name or "unknown"
        if stage_name not in self.stages:
            self.stages[stage_name] = StageTokenStats(stage_name=stage_name)
        self.stages[stage_name].add_usage(prompt_tokens, candidate_tokens, total_tokens)
        self.total_prompt_tokens += prompt_tokens
        self.total_candidate_tokens += candidate_tokens
        self.total_tokens += total_tokens
        self.total_llm_calls += 1

    def to_dict(self) -> Dict[str, Any]:
        """把报告序列化为 dict。"""
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
        """供人阅读的汇总文本。"""
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
