from typing import Optional, Dict, Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.models import LlmResponse
from google.genai import types


async def human_review_callback(
    callback_context: CallbackContext,
    agent_result: types.Content
) -> Optional[LlmResponse]:
    """Human-in-the-loop callback triggered after scheduler agent completes.

    Based on analysis_phase, triggers appropriate review stage.
    """
    state = callback_context.state
    phase = state.get("analysis_phase", "initial")

    if phase == "initial_complete":
        return await _trigger_initial_review(state)

    return None


async def _trigger_initial_review(state: Dict[str, Any]) -> LlmResponse:
    """Trigger initial analysis review after Phase 0 + Phase 1 complete."""

    # Collect all worker outputs
    string_analysis = state.get("string_analysis", {})
    api_behavior = state.get("api_behavior_analysis", {})
    export_interface = state.get("export_interface_analysis", {})
    behavior_profile = state.get("behavior_profile", {})
    function_boundary = state.get("function_boundary_analysis", {})

    # Extract key findings
    behavior_type = behavior_profile.get("behavior_profile", {}).get("primary_type", "Unknown")
    confidence = behavior_profile.get("behavior_profile", {}).get("confidence", "low")

    high_risk_strings = [
        s for s in string_analysis.get("suspicious_patterns", [])
        if s.get("risk_level") == "high"
    ]

    high_risk_apis = [
        api for api in api_behavior.get("suspicious_apis", [])
        if api.get("threat_category") in ["进程注入", "持久化", "网络通信"]
    ]

    candidates = function_boundary.get("candidates", [])[:20]
    total_funcs = function_boundary.get("total_functions", 0)

    # Build review payload
    review_payload = {
        "review_type": "initial_analysis_review",
        "behavior_profile": {
            "primary_type": behavior_type,
            "confidence": confidence,
        },
        "high_risk_findings": {
            "string_indicators": len(high_risk_strings),
            "api_indicators": len(high_risk_apis),
        },
        "candidate_functions": {
            "total": total_funcs,
            "top_20": candidates,
        },
        "checklist_status": behavior_profile.get("analysis_checklist", {}),
        "instructions": (
            "=== 恶意样本初步分析审查 ===\n\n"
            f"行为定型: {behavior_type} (置信度: {confidence})\n"
            f"高风险字符串指标: {len(high_risk_strings)}\n"
            f"高风险 API 指标: {len(high_risk_apis)}\n"
            f"候选函数: {len(candidates)} / {total_funcs}\n\n"
            "请审查以上分析结论，确认：\n"
            "1. 行为定型是否合理\n"
            "2. 候选函数列表是否需要调整（排除/补充）\n"
            "3. 是否需要继续深入分析特定函数\n\n"
            "回复格式: CONFIRM 或 MODIFY [具体修正内容]"
        ),
    }

    state["pending_human_review"] = review_payload
    state["execution_status"] = "WAITING_FOR_APPROVAL"

    # Build summary text for the response
    summary_lines = [
        f"[SYSTEM] 初步分析完成。样本定型: {behavior_type} (置信度: {confidence})",
        f"[SYSTEM] 发现 {len(high_risk_strings)} 个高风险字符串指标，{len(high_risk_apis)} 个高风险 API 指标。",
        f"[SYSTEM] 函数列表共 {total_funcs} 个，推荐分析前 {len(candidates)} 个候选函数。",
        "[SYSTEM] 请审查分析结论并确认下一步方向。",
    ]

    return LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part(text="\n".join(summary_lines))]
        )
    )
