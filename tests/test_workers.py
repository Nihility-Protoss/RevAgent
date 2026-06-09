from workers.phase0.string_artifact_analyst import string_artifact_analyst
from workers.phase0.api_behavior_profiler import api_behavior_profiler
from workers.phase0.export_interface_analyzer import export_interface_analyzer
from workers.phase1.behavior_profile_synthesizer import behavior_profile_synthesizer
from workers.phase1.function_boundary_detector import function_boundary_detector
from callbacks.human_review import human_review_callback
import inspect


def test_string_artifact_analyst_exists():
    assert string_artifact_analyst is not None
    assert string_artifact_analyst.name == "string_artifact_analyst"
    assert string_artifact_analyst.output_key == "string_analysis"


def test_api_behavior_profiler_exists():
    assert api_behavior_profiler is not None
    assert api_behavior_profiler.name == "api_behavior_profiler"
    assert api_behavior_profiler.output_key == "api_behavior_analysis"


def test_export_interface_analyzer_exists():
    assert export_interface_analyzer is not None
    assert export_interface_analyzer.name == "export_interface_analyzer"
    assert export_interface_analyzer.output_key == "export_interface_analysis"


def test_behavior_profile_synthesizer_exists():
    assert behavior_profile_synthesizer is not None
    assert behavior_profile_synthesizer.name == "behavior_profile_synthesizer"
    assert behavior_profile_synthesizer.output_key == "behavior_profile"


def test_function_boundary_detector_exists():
    assert function_boundary_detector is not None
    assert function_boundary_detector.name == "function_boundary_detector"
    assert function_boundary_detector.output_key == "function_boundary_analysis"


def test_human_review_callback_is_async():
    assert inspect.iscoroutinefunction(human_review_callback)


def test_all_workers_have_data_sufficiency_in_instruction():
    """All workers must reference data sufficiency check in their instruction."""
    from workers.phase0.string_artifact_analyst import string_artifact_analyst
    from workers.phase0.api_behavior_profiler import api_behavior_profiler
    from workers.phase0.export_interface_analyzer import export_interface_analyzer
    from workers.phase1.behavior_profile_synthesizer import behavior_profile_synthesizer
    from workers.phase1.function_boundary_detector import function_boundary_detector
    from workers.phase3.function_deep_analyzer import function_deep_analyzer

    workers = [
        string_artifact_analyst,
        api_behavior_profiler,
        export_interface_analyzer,
        behavior_profile_synthesizer,
        function_boundary_detector,
    ]
    for w in workers:
        assert "insufficient_data" in w.instruction, f"{w.name} missing insufficient_data check"
        assert "status" in w.instruction, f"{w.name} missing status field requirement"


def test_phase3_prompt_has_insufficient_data_exit():
    """Phase 3 prompt must have explicit insufficient_data exit condition."""
    from workers.phase3.function_deep_analyzer import FUNC_ANALYSIS_PROMPT_TEMPLATE
    assert "insufficient_data" in FUNC_ANALYSIS_PROMPT_TEMPLATE
    assert "代码片段不足" in FUNC_ANALYSIS_PROMPT_TEMPLATE
