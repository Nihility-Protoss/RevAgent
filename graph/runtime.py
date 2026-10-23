"""LLM 运行时基础设施：共享模型、上下文预算与 JSON 容错解析。"""
import json
import os
from typing import Any, Optional

from dotenv import load_dotenv
from langchain.chat_models import init_chat_model
from langchain_core.messages.utils import convert_to_messages, count_tokens_approximately
from langchain_core.runnables import RunnableConfig

from config import cfg, cfg_int


# === LLM 构造（环境变量与 ADK 版保持一致）===

_LLM = None


def get_llm():
    """返回共享 chat model（优先级：config.yaml > 环境变量 > 默认值）。

    API key 解析：`llm.api_key` 字面量优先；否则读取 `llm.api_key_env`
    指定的环境变量（默认 API_KEY，密钥本身仍留在 .env 中）。
    """
    global _LLM
    if _LLM is None:
        load_dotenv()
        api_key = cfg("llm.api_key")
        if not api_key:
            api_key = os.getenv(cfg("llm.api_key_env", default="API_KEY"))
        # 思考模式与 create_agent 的强制 tool_choice（结构化输出）不兼容，
        # 默认关闭；需要思考模式时在 config.yaml 设 llm.thinking=enabled。
        _LLM = init_chat_model(
            cfg("llm.model", env="MODEL", default="deepseek-flash"),
            model_provider="openai",
            api_key=api_key,
            base_url=cfg("llm.base_url", env="BASE_URL", default="https://api.deepseek.com/v1"),
            temperature=0,
            max_retries=3,
            extra_body={"thinking": {"type": cfg("llm.thinking", env="THINKING", default="disabled")}},
        )
    return _LLM


def set_llm(llm) -> None:
    """注入一个模型实例（供测试离线运行使用）。
    """
    global _LLM
    _LLM = llm


# === 上下文预算（所有 agent 共享 128k 上限）===

def max_context_tokens() -> int:
    """单次 LLM 调用的输入 token 上限（config.yaml llm.max_context_tokens，默认 128k）。
    """
    return cfg_int("llm.max_context_tokens", env="MAX_CONTEXT_TOKENS", default=128000)


# ReAct 循环内历史超过该阈值即触发摘要压缩（留 ~25% 余量给输出与系统提示）
def _summary_trigger_tokens() -> int:
    return int(max_context_tokens() * 0.75)


def enforce_context_budget(messages: list) -> list:
    """裁剪消息内容，使总体估算量落在上下文预算内。

    策略：优先截断最长的消息内容（从文本中间截掉，保留头尾）；若仍超预算则抛出 RuntimeError。
    """
    budget = max_context_tokens()
    normalized = convert_to_messages(messages)

    for _round in range(3):
        total = count_tokens_approximately(normalized)
        if total <= budget:
            return normalized

        # 估算每条消息的 token，用于定位可截断的大消息
        per_msg = [count_tokens_approximately([m]) for m in normalized]
        excess = total - budget
        # 从大到小截断，正文保留头尾各一半
        order = sorted(range(len(normalized)), key=lambda i: per_msg[i], reverse=True)
        for i in order:
            if excess <= 0:
                break
            content = normalized[i].content
            if not isinstance(content, str):
                continue
            # 保底留 ~50 tokens（头尾各约 100 字符），其余都可截掉
            max_cut = max(per_msg[i] - 50, 0)
            # 过切 20% + 16 tokens，覆盖截断标记与估算误差，避免多轮不收敛
            cut = min(int(excess * 1.2) + 16, max_cut)
            if cut <= 0:
                continue
            keep_chars = max(len(content) - cut * 4, 200)
            half = keep_chars // 2
            normalized[i] = normalized[i].model_copy(update={
                "content": content[:half] + "\n...[内容过长已截断]...\n" + content[-half:],
            })
            excess -= cut

    final = count_tokens_approximately(normalized)
    if final > budget:
        raise RuntimeError(
            f"prompt 估算 {final} tokens 超过上下文上限 {budget}，"
            "截断后仍无法容纳，请减小输入分片或调高 MAX_CONTEXT_TOKENS"
        )
    return normalized


async def invoke_guarded(model, messages: list, config: Optional[RunnableConfig] = None):
    """带上下文预算约束的 ainvoke（默认 128k）。
    """
    return await model.ainvoke(enforce_context_budget(messages), config=config)


# === 通用辅助 ===

def parse_json_loose(text: Any) -> dict:
    """尽力解析模型输出的 JSON，永不抛异常。
    """
    if isinstance(text, dict):
        return text
    if not isinstance(text, str):
        return {"status": "parse_failed", "raw": str(text), "parse_error": True}
    stripped = text.strip()
    # 去掉可能的 markdown 代码围栏
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = [l for l in lines if not l.strip().startswith("```")]
        stripped = "\n".join(lines).strip()
    try:
        data = json.loads(stripped)
        return data if isinstance(data, dict) else {"status": "success", "data": data}
    except (json.JSONDecodeError, ValueError):
        return {"status": "parse_failed", "raw": text, "parse_error": True}
