from workers.phase4.synthesis_agent import (
    synthesis_agent,
    synthesis_shard_agent,
    aggregator_agent,
    SHARD_SYNTHESIS_PROMPT,
    AGGREGATOR_PROMPT,
)


def test_synthesis_agent_exists():
    assert synthesis_agent.name == "synthesis_aggregator"


def test_shard_agent_exists():
    assert synthesis_shard_agent.name == "synthesis_shard"


def test_aggregator_agent_exists():
    assert aggregator_agent.name == "synthesis_aggregator"


def test_shard_prompt_contains_key_fields():
    assert "shard_id" in SHARD_SYNTHESIS_PROMPT
    assert "status" in SHARD_SYNTHESIS_PROMPT
    assert "suspicious_functions_summary" in SHARD_SYNTHESIS_PROMPT


def test_aggregator_prompt_contains_key_fields():
    assert "malware_family" in AGGREGATOR_PROMPT
    assert "uncertainties" in AGGREGATOR_PROMPT
    assert "shard_report" in AGGREGATOR_PROMPT
