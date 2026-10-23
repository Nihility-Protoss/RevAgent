"""上下文预算（128k）的纯单元测试。"""
import pytest


def _write_config(tmp_path, text):
    """写入临时目录的 config.yaml 并重置快照，使后续 cfg() 读到新内容。"""
    from config import reset_config_cache

    (tmp_path / "config.yaml").write_text(text, encoding="utf-8")
    reset_config_cache()


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
    # chdir 到临时目录并用 config.yaml 收紧预算（无环境变量回退）
    monkeypatch.chdir(tmp_path)
    _write_config(tmp_path, "llm:\n  max_context_tokens: 2000\n")
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
    _write_config(tmp_path, "llm:\n  max_context_tokens: 1\n")
    with pytest.raises(RuntimeError, match="上下文上限"):
        enforce_context_budget([("user", "x" * 4000)])


def test_max_context_tokens_default(monkeypatch, tmp_path):
    from graph.runtime import max_context_tokens
    monkeypatch.chdir(tmp_path)  # 无 config.yaml：使用代码默认值
    assert max_context_tokens() == 128000
    _write_config(tmp_path, "llm:\n  max_context_tokens: 64000\n")
    assert max_context_tokens() == 64000
