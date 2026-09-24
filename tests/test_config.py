"""config.py 测试（config.yaml 全局配置读写）。
"""
import os

import pytest

import config
from config import cfg, cfg_bool, cfg_int, load_config, write_config


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
    assert load_config() == {}
