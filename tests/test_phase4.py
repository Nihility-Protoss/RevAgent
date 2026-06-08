from workers.phase4.synthesis_agent import synthesis_agent, FINAL_SYNTHESIS_PROMPT


def test_synthesis_agent_exists():
    assert synthesis_agent.name == "final_synthesis"


def test_prompt_contains_all_phases():
    assert "phase0" in FINAL_SYNTHESIS_PROMPT
    assert "phase1" in FINAL_SYNTHESIS_PROMPT
    assert "phase3" in FINAL_SYNTHESIS_PROMPT
    assert "malware_family" in FINAL_SYNTHESIS_PROMPT
