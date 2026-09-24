"""Phase 4 综合 prompt 测试（LangGraph 迁移后）。

ADK agents（synthesis_shard / synthesis_aggregator）已移除；Phase 4 现在由
graph 节点（make_shard_synthesis_node / make_aggregator_node）驱动，使用此处断言的
prompt 常量。
"""
from workers.phase4.synthesis_agent import AGGREGATOR_PROMPT, SHARD_SYNTHESIS_PROMPT


def test_shard_synthesis_prompt_is_preserved():
    """Phase 4 Map 步骤需要带局部分析模式的 shard prompt。
    """
    assert "局部分析模式" in SHARD_SYNTHESIS_PROMPT
    assert "shard_id" in SHARD_SYNTHESIS_PROMPT


def test_aggregator_prompt_is_preserved():
    """Phase 4 Reduce 步骤需要带必需字段的 aggregator prompt。
    """
    assert "汇总模式" in AGGREGATOR_PROMPT
    assert "malware_family" in AGGREGATOR_PROMPT
    assert "uncertainties" in AGGREGATOR_PROMPT


def test_aggregator_prompt_requires_uncertainties():
    """Aggregator 必须要求 uncertainties 非空。
    """
    assert "uncertainties 字段必须非空" in AGGREGATOR_PROMPT


def test_aggregator_prompt_family_constraint():
    """Aggregator 仅在 ≥2 个 shard 一致时才可输出家族名。
    """
    assert "≥2 个 shard 一致支持" in AGGREGATOR_PROMPT
    assert "Unknown" in AGGREGATOR_PROMPT
