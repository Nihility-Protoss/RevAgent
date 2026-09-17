"""Helpers for parsing ADK session state values.

ADK 2.2.0 stores an LlmAgent's output_key as a raw JSON string when no
output_schema is configured, so every consumer must tolerate dict or str.
"""
import json
from typing import Any


def coerce_state_dict(value: Any) -> dict:
    """Return value as a dict, tolerating ADK's raw-JSON-string storage.

    dict passes through; str is parsed via json.loads and returned only when
    it decodes to a dict; everything else becomes {}. Never raises.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def extract_arch_detection(state_value: Any) -> dict:
    """Extract arch_detection from a Phase 0 worker state value.

    Accepts dict, JSON str, or anything else (returns {}).
    """
    return coerce_state_dict(state_value).get("arch_detection") or {}
