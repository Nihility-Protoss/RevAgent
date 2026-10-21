"""上下文预算（128k）的纯单元测试。"""
import pytest


# === 上下文预算（128k） =================================================================

def test_enforce_context_budget_passthrough():
    """小体积 prompt 原样返回（会先被规范化为 messages）。"""
    from graph.runtime import enforce_context_budget
    messages = [("system", "sys"), ("user", "hello")]
    result = enforce_context_budget(messages)
    assert len(result) == 2
    assert result[1].content == "hello"


def test_enforce_context_budget_truncates_oversized(monkeypatch, tmp_path):
    """单条超大消息会被截断以适配预算。"""
    from graph.runtime import enforce_context_budget
    # chdir 到无 config.yaml 的目录，让 MAX_CONTEXT_TOKENS 环境变量回退生效
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MAX_CONTEXT_TOKENS", "2000")
    big = "A" * 40000  # ~10k tokens，远超 2000 的预算
    result = enforce_context_budget([("user", big)])
    assert len(result) == 1
    assert "已截断" in result[0].content
    assert len(result[0].content) < len(big)
    # 头尾证据保留
    assert result[0].content.startswith("AAA")
    assert result[0].content.endswith("AAA")


def test_enforce_context_budget_raises_when_impossible(monkeypatch, tmp_path):
    """预算小到什么都装不下时必须抛出明确的错误。"""
    from graph.runtime import enforce_context_budget
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MAX_CONTEXT_TOKENS", "1")
    with pytest.raises(RuntimeError, match="上下文上限"):
        enforce_context_budget([("user", "x" * 4000)])


def test_max_context_tokens_default(monkeypatch, tmp_path):
    from graph.runtime import max_context_tokens
    monkeypatch.chdir(tmp_path)  # 避开仓库根目录的 config.yaml
    monkeypatch.delenv("MAX_CONTEXT_TOKENS", raising=False)
    assert max_context_tokens() == 128000
    monkeypatch.setenv("MAX_CONTEXT_TOKENS", "64000")
    assert max_context_tokens() == 64000
