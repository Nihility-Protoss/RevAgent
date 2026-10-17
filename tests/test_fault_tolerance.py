def test_checkpoint_recovers_from_runtime_store(tmp_path, monkeypatch):
    from tools.entry_store import shutdown_stores
    from tools.entry_tools import (
        bb_checkpoint, bb_load_checkpoint, bb_log_event, bb_set_runtime,
    )

    monkeypatch.chdir(tmp_path)
    bb_set_runtime("run_id", "run-1", "proj")
    bb_checkpoint("phase0_complete", "proj")
    bb_log_event("worker_failed", {"worker": "api", "reason": "timeout"}, "proj")
    shutdown_stores()
    checkpoint = bb_load_checkpoint("proj")
    assert checkpoint["current_phase"] == "phase0_complete"
    assert checkpoint["run_id"] == "run-1"
