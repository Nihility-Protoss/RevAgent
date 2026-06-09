from workers.phase4.synthesis_agent import synthesis_agent, synthesis_shard_agent, aggregator_agent


def test_synthesis_agent_exists():
    assert synthesis_agent.name == "synthesis_aggregator"


def test_synthesis_shard_agent_exists():
    """Phase 4 Map-Reduce requires shard agent."""
    assert synthesis_shard_agent.name == "synthesis_shard"
    assert "局部分析模式" in synthesis_shard_agent.instruction
    assert "shard_id" in synthesis_shard_agent.instruction


def test_aggregator_agent_exists():
    """Phase 4 Map-Reduce requires aggregator agent."""
    assert aggregator_agent.name == "synthesis_aggregator"
    assert "汇总模式" in aggregator_agent.instruction
    assert "malware_family" in aggregator_agent.instruction
    assert "uncertainties" in aggregator_agent.instruction


def test_aggregator_prompt_requires_uncertainties():
    """Aggregator must require non-empty uncertainties."""
    assert "uncertainties 字段必须非空" in aggregator_agent.instruction


def test_aggregator_prompt_family_constraint():
    """Aggregator must only output family name when ≥2 shards agree."""
    assert "≥2 个 shard 一致支持" in aggregator_agent.instruction
    assert "Unknown" in aggregator_agent.instruction
