import os
import json
import tempfile
import pytest

from tools.blackboard_tools import (
    bb_read_extract, bb_read_summary, bb_write_summary,
    bb_write_artifact, bb_list_summaries, bb_has_artifact,
    bb_checkpoint, bb_load_checkpoint, bb_log_event,
)


def _make_board(project_name, base_dir):
    board_dir = os.path.join(base_dir, ".blackboard", project_name)
    for sub in ["extracts", "artifacts", "summary", "meta"]:
        os.makedirs(os.path.join(board_dir, sub), exist_ok=True)
    return board_dir


def test_bb_write_and_read_summary():
    orig_dir = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_board("test_proj", tmpdir)
        os.chdir(tmpdir)
        try:
            result = bb_write_summary("p0_strings", {"key": "value"}, "test_proj")
            assert result["status"] == "success"

            read = bb_read_summary("p0_strings", "test_proj")
            assert read["data"]["key"] == "value"
        finally:
            os.chdir(orig_dir)


def test_bb_summary_token_limit():
    orig_dir = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_board("test_proj", tmpdir)
        os.chdir(tmpdir)
        try:
            large_data = {"items": ["x" * 100 for _ in range(100)]}
            result = bb_write_summary("p0_large", large_data, "test_proj")
            assert result["status"] == "error"
            assert "summary_too_large" in result["reason"]
        finally:
            os.chdir(orig_dir)


def test_bb_checkpoint_and_load():
    orig_dir = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_board("test_proj", tmpdir)
        os.chdir(tmpdir)
        try:
            assert bb_load_checkpoint("test_proj") is None

            bb_checkpoint("phase0_complete", "test_proj")
            cp = bb_load_checkpoint("test_proj")
            assert cp is not None
            assert cp["current_phase"] == "phase0_complete"
        finally:
            os.chdir(orig_dir)


def test_bb_has_artifact():
    orig_dir = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_board("test_proj", tmpdir)
        os.chdir(tmpdir)
        try:
            assert not bb_has_artifact("p0_string", "test_proj")
            bb_write_artifact("p0_string", {"result": "test"}, "test_proj")
            assert bb_has_artifact("p0_string", "test_proj")
        finally:
            os.chdir(orig_dir)


def test_bb_log_event():
    orig_dir = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_board("test_proj", tmpdir)
        os.chdir(tmpdir)
        try:
            bb_log_event("worker_failed", {"worker": "test", "reason": "timeout"}, "test_proj")
            log_path = os.path.join(tmpdir, ".blackboard", "test_proj", "meta", "execution_log.jsonl")
            assert os.path.exists(log_path)
            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            assert len(lines) == 1
            entry = json.loads(lines[0])
            assert entry["event_type"] == "worker_failed"
        finally:
            os.chdir(orig_dir)
