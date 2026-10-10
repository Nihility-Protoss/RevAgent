"""基于 LangGraph callback 的 token 用量可观测性。

取代 ADK 的事件遍历统计：由 BaseCallbackHandler 从 LLM 调用中按节点聚合 token 用量，
自动覆盖每个 Phase（含 Phase 3/4）。输出格式保持与 AnalysisTokenReport 兼容。

模块级注册表（register_callback / current_total_tokens）供 token 预算闸门
（graph_nodes._enforce_token_budget）查询项目实时累计用量。
"""
from typing import Any, Optional
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from tools.token_stats import AnalysisTokenReport


# === 模块级 callback 注册表（token 预算闸门的数据源）===

_CALLBACK_REGISTRY: dict = {}


def register_callback(project_name: str, callback: "TokenStatsCallback") -> None:
    """注册项目的 TokenStatsCallback（main.py 创建时调用），供预算闸门查询实时用量。

    同项目重复注册会覆盖旧记录（新一轮运行重新计数）。
    """
    _CALLBACK_REGISTRY[project_name] = callback


def current_total_tokens(project_name: str) -> int:
    """项目当前累计 total tokens；未注册（如未挂 callback 的测试图）返回 0，
    预算闸门据此视为未超预算（不启用侧退化为无操作）。"""
    callback = _CALLBACK_REGISTRY.get(project_name)
    return callback.report.total_tokens if callback is not None else 0


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
