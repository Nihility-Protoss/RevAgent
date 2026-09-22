"""Tests for Phase 4 synthesis prompts (post LangGraph migration).

The ADK agents (synthesis_shard / synthesis_aggregator) are gone; Phase 4 runs
as graph nodes (make_shard_synthesis_node / make_aggregator_node) driven by the
prompt constants asserted here.
"""
from workers.phase4.synthesis_agent import AGGREGATOR_PROMPT, SHARD_SYNTHESIS_PROMPT


def test_shard_synthesis_prompt_is_preserved():
    """Phase 4 Map step requires the shard prompt with local-analysis mode."""
    assert "局部分析模式" in SHARD_SYNTHESIS_PROMPT
    assert "shard_id" in SHARD_SYNTHESIS_PROMPT


def test_aggregator_prompt_is_preserved():
    """Phase 4 Reduce step requires the aggregator prompt with required fields."""
    assert "汇总模式" in AGGREGATOR_PROMPT
    assert "malware_family" in AGGREGATOR_PROMPT
    assert "uncertainties" in AGGREGATOR_PROMPT


def test_aggregator_prompt_requires_uncertainties():
    """Aggregator must require non-empty uncertainties."""
    assert "uncertainties 字段必须非空" in AGGREGATOR_PROMPT


def test_aggregator_prompt_family_constraint():
    """Aggregator must only output family name when ≥2 shards agree."""
    assert "≥2 个 shard 一致支持" in AGGREGATOR_PROMPT
    assert "Unknown" in AGGREGATOR_PROMPT
