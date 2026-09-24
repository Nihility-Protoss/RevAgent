import json
import tempfile
import os
import sys

from tools.blackboard_tools import bb_write_summary, board_path


def test_summary_too_large_rejected():
    # Windows 下清理期间文件句柄可能仍未释放
    ignore_cleanup = sys.platform == "win32"
    orig_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=ignore_cleanup) as tmpdir:
        os.chdir(tmpdir)
        try:
            os.makedirs(board_path("test", "summary"), exist_ok=True)

            large = {"items": ["x" * 200 for _ in range(200)]}  # 约 40k 字符 = 约 10k tokens
            result = bb_write_summary("too_big", large, "test")
            assert result["status"] == "error"
            assert "summary_too_large" in result["reason"]
        finally:
            os.chdir(orig_cwd)


def test_state_recovery_after_worker_failure():
    """模拟场景：checkpoint 已存在、worker 状态为 failed，应当跳过。"""
    ignore_cleanup = sys.platform == "win32"
    orig_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=ignore_cleanup) as tmpdir:
        os.chdir(tmpdir)
        try:
            from tools.blackboard_tools import bb_checkpoint, bb_load_checkpoint, bb_log_event

            bb_checkpoint("phase0_complete", "test")
            bb_log_event("worker_failed", {"worker": "test_worker", "reason": "timeout"}, "test")

            state = bb_load_checkpoint("test")
            assert state["current_phase"] == "phase0_complete"
        finally:
            os.chdir(orig_cwd)
