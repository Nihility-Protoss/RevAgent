"""Token 报告的纯单元测试（AnalysisTokenReport / StageTokenStats）。"""
from tools.token_stats import AnalysisTokenReport, StageTokenStats


# === Token 报告（AnalysisTokenReport.add_usage） ======================================

def test_token_report_basic():
    """测试 AnalysisTokenReport 能正确收集用量。"""
    report = AnalysisTokenReport(sample_project_name="test")
    report.add_usage("test_node", 100, 50, 150)

    assert report.total_prompt_tokens == 100
    assert report.total_candidate_tokens == 50
    assert report.total_tokens == 150
    assert report.total_llm_calls == 1
    assert "test_node" in report.stages
    assert report.stages["test_node"].prompt_tokens == 100

    d = report.to_dict()
    assert d["sample_project_name"] == "test"
    assert d["total_llm_calls"] == 1
    assert d["stages"]["test_node"]["call_count"] == 1


def test_token_report_accumulates_multiple_stages():
    report = AnalysisTokenReport(sample_project_name="test")
    report.add_usage("scheduler", 100, 50, 150)
    report.add_usage("scheduler", 10, 5, 15)
    report.add_usage("aggregator", 1000, 500, 1500)

    assert report.total_llm_calls == 3
    assert report.total_tokens == 1665
    assert report.stages["scheduler"].call_count == 2
    assert report.stages["aggregator"].prompt_tokens == 1000


def test_token_report_str_output():
    """测试 AnalysisTokenReport 的字符串表示。"""
    report = AnalysisTokenReport(sample_project_name="test")
    report.add_usage("scheduler", 1000, 500, 1500)
    output = str(report)

    assert "Token Usage Report: test" in output
    assert "Total LLM Calls: 1" in output
    assert "Total Tokens: 1,500" in output
    assert "scheduler" in output


def test_stage_token_stats_add_usage():
    """测试 StageTokenStats 累加用量。"""
    stats = StageTokenStats(stage_name="test_stage")
    stats.add_usage(100, 50, 150)
    assert stats.prompt_tokens == 100
    assert stats.candidate_tokens == 50
    assert stats.total_tokens == 150
    assert stats.call_count == 1

    stats.add_usage(100, 50, 150)
    assert stats.prompt_tokens == 200
    assert stats.call_count == 2
