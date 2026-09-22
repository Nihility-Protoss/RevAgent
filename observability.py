"""LangGraph callback-based token usage observability.

Replaces ADK event-traversal statistics: a BaseCallbackHandler aggregates
per-node token usage from LLM calls, covering every phase (including
Phase 3/4) automatically. Output format stays AnalysisTokenReport-compatible.
"""
from typing import Any, Optional
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from tools.token_stats import AnalysisTokenReport


class TokenStatsCallback(BaseCallbackHandler):
    """Aggregate LLM token usage per graph node (via langgraph_node metadata)."""

    def __init__(self, sample_project_name: str):
        super().__init__()
        self.report = AnalysisTokenReport(sample_project_name=sample_project_name)
        self._run_stages: dict[UUID, str] = {}

    def on_llm_start(
        self,
        serialized: dict,
        prompts: list[str],
        *,
        run_id: UUID,
        metadata: Optional[dict] = None,
        **kwargs: Any,
    ) -> None:
        self._run_stages[run_id] = (metadata or {}).get("langgraph_node", "unknown")

    def on_chat_model_start(
        self,
        serialized: dict,
        messages: list,
        *,
        run_id: UUID,
        metadata: Optional[dict] = None,
        **kwargs: Any,
    ) -> None:
        self._run_stages[run_id] = (metadata or {}).get("langgraph_node", "unknown")

    def on_llm_end(self, response: LLMResult, *, run_id: UUID, **kwargs: Any) -> None:
        stage = self._run_stages.pop(run_id, "unknown")
        usage = self._extract_usage(response)
        if usage is None:
            return
        prompt, candidate, total = usage
        self.report.add_usage(stage, prompt, candidate, total)

    @staticmethod
    def _extract_usage(response: LLMResult) -> Optional[tuple[int, int, int]]:
        """Extract (prompt, candidate, total) token counts from an LLMResult."""
        usage = None
        try:
            usage = response.generations[0][0].message.usage_metadata
        except (IndexError, AttributeError, TypeError):
            usage = None
        if not usage and response.llm_output:
            usage = response.llm_output.get("token_usage") or response.llm_output.get("usage")
        if not usage:
            return None
        prompt = usage.get("input_tokens") or usage.get("prompt_tokens") or 0
        candidate = usage.get("output_tokens") or usage.get("completion_tokens") or 0
        total = usage.get("total_tokens") or (prompt + candidate)
        return prompt, candidate, total
