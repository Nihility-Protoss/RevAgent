"""基于 LangGraph callback 的 token 用量可观测性。

取代 ADK 的事件遍历统计：由 BaseCallbackHandler 从 LLM 调用中按节点聚合 token 用量，
自动覆盖每个 Phase（含 Phase 3/4）。输出格式保持与 AnalysisTokenReport 兼容。
"""
from typing import Any, Optional
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from tools.token_stats import AnalysisTokenReport


class TokenStatsCallback(BaseCallbackHandler):
    """按 graph 节点聚合 LLM token 用量（依据 langgraph_node metadata）。
    """

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
        """从 LLMResult 中提取 (prompt, candidate, total) 三个 token 计数。
        """
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
