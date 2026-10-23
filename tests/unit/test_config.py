"""config.py 测试（config.yaml 全局配置读写）。
"""
import os

import pytest

import config
from config import cfg, cfg_bool, cfg_int, load_config, reset_config_cache, write_config


@pytest.fixture()
def workdir(tmp_path, monkeypatch):
    """chdir 到不含 config.yaml 的临时目录，测试结束自动还原。
    """
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _write_yaml(workdir, text):
    path = os.path.join(str(workdir), "config.yaml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def test_cfg_reads_yaml(workdir):
    _write_yaml(workdir, "llm:\n  model: test-model\n  max_context_tokens: 64000\n")
    assert cfg("llm.model") == "test-model"
    assert cfg_int("llm.max_context_tokens") == 64000


def test_cfg_env_fallback_and_default(workdir, monkeypatch):
    # 无 config.yaml：环境变量优先于默认值
    monkeypatch.setenv("MODEL", "env-model")
    assert cfg("llm.model", env="MODEL", default="d") == "env-model"
    monkeypatch.delenv("MODEL")
    assert cfg("llm.model", env="MODEL", default="d") == "d"
    assert cfg("missing.key") is None


def test_cfg_yaml_beats_env(workdir, monkeypatch):
    _write_yaml(workdir, "llm:\n  model: yaml-model\n")
    monkeypatch.setenv("MODEL", "env-model")
    assert cfg("llm.model", env="MODEL") == "yaml-model"


def test_cfg_bool(workdir):
    _write_yaml(workdir, "analysis:\n  resume: true\n")
    assert cfg_bool("analysis.resume") is True
    assert cfg_bool("analysis.missing", default=False) is False


def test_cfg_none_value_falls_back(workdir, monkeypatch):
    # yaml 中显式 null 视为缺失，回退环境变量
    _write_yaml(workdir, "analysis:\n  input_name: null\n")
    monkeypatch.setenv("INPUT_NAME", "env-input")
    assert cfg("analysis.input_name", env="INPUT_NAME") == "env-input"


def test_write_config_roundtrip_and_merge(workdir):
    _write_yaml(workdir, "llm:\n  model: old\n  base_url: http://a\n")
    write_config({"llm": {"model": "new"}, "analysis": {"project_name": "p1"}})
    data = load_config()
    assert data["llm"]["model"] == "new"       # 覆盖
    assert data["llm"]["base_url"] == "http://a"  # 深合并保留
    assert data["analysis"]["project_name"] == "p1"  # 新增分支
    # 值为 None 表示删除键
    write_config({"analysis": {"project_name": None}})
    assert "project_name" not in load_config()["analysis"]


def test_load_config_missing_and_empty(workdir):
    assert load_config() == {}
    _write_yaml(workdir, "")
    reset_config_cache()  # 快照已冻结，需显式重置才能读到刚写入的空文件
    assert load_config() == {}


# === 快照语义 ===========================================================================

def test_snapshot_freezes_first_read(workdir):
    """首次读取后改写 config.yaml 不影响本进程的快照值。"""
    path = _write_yaml(workdir, "llm:\n  model: first\n")
    assert cfg("llm.model") == "first"
    # 模拟另一进程在运行中途改写共享配置
    with open(path, "w", encoding="utf-8") as f:
        f.write("llm:\n  model: second\n")
    assert cfg("llm.model") == "first"
    assert load_config()["llm"]["model"] == "first"


def test_reset_config_cache_reads_new_content(workdir):
    """reset_config_cache() 后重新读盘生成新快照。"""
    path = _write_yaml(workdir, "llm:\n  model: first\n")
    assert cfg("llm.model") == "first"
    with open(path, "w", encoding="utf-8") as f:
        f.write("llm:\n  model: second\n")
    reset_config_cache()
    assert cfg("llm.model") == "second"


def test_snapshot_survives_concurrent_rewrite_after_write(workdir):
    """write_config 写盘后可立即被另一进程改写，本进程读取不受中途改写影响。"""
    path = _write_yaml(workdir, "llm:\n  model: old\n")
    write_config({"llm": {"model": "mine"}})
    assert cfg("llm.model") == "mine"
    # 另一进程紧跟着改写同一文件
    with open(path, "w", encoding="utf-8") as f:
        f.write("llm:\n  model: other-process\n")
    assert cfg("llm.model") == "mine"
    # 本进程主动重载后才看到新内容
    reset_config_cache()
    assert cfg("llm.model") == "other-process"


def test_entry_tool_and_persistence_defaults():
    from pathlib import Path

    import yaml

    data = yaml.safe_load(
        (Path(__file__).parents[2] / "config.yaml").read_text(encoding="utf-8")
    )
    assert data["agents"]["tool_mode"] == "minimal"
    assert data["llm"]["api_key_env"] == "API_KEY"
    assert data["blackboard"]["flush_every_writes"] == 20
    assert data["blackboard"]["flush_interval_seconds"] == 5
    assert data["blackboard"]["backup_limit"] == 10
