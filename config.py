"""全局配置：根目录 config.yaml 的统一读写入口。

优先级：CLI 参数 > config.yaml > 环境变量 > 默认值。
config.yaml 相对当前工作目录解析，按文件 mtime 缓存；
API_KEY 等机密仍建议放 .env，不要写入 config.yaml。
"""
import os
from typing import Any, Optional

import yaml

CONFIG_FILENAME = "config.yaml"

_cache: dict = {}
_cache_key: Optional[tuple] = None


def config_path() -> str:
    """当前工作目录下的 config.yaml 路径。"""
    return os.path.join(os.getcwd(), CONFIG_FILENAME)


def load_config() -> dict:
    """读取 config.yaml（不存在或为空返回 {}），按 (路径, mtime) 缓存。"""
    global _cache, _cache_key
    path = config_path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        _cache, _cache_key = {}, None
        return _cache
    key = (path, mtime)
    if key != _cache_key:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _cache = data if isinstance(data, dict) else {}
        _cache_key = key
    return _cache


def cfg(key_path: str, env: Optional[str] = None, default: Any = None) -> Any:
    """按点分路径读取配置（如 "llm.model"）；yaml 缺失时回退环境变量，再回退默认值。"""
    node: Any = load_config()
    for part in key_path.split("."):
        if not isinstance(node, dict) or part not in node:
            node = None
            break
        node = node[part]
    if node is not None:
        return node
    if env:
        value = os.getenv(env)
        if value is not None:
            return value
    return default


def cfg_int(key_path: str, env: Optional[str] = None, default: int = 0) -> int:
    """cfg() 的 int 版本。"""
    return int(cfg(key_path, env=env, default=default))


def cfg_bool(key_path: str, env: Optional[str] = None, default: bool = False) -> bool:
    """cfg() 的 bool 版本（兼容 yaml 布尔与环境变量字符串）。"""
    value = cfg(key_path, env=env, default=None)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _deep_merge(base: dict, updates: dict) -> dict:
    """递归合并 updates 到 base（updates 优先，值为 None 表示删除该键）。"""
    for key, value in updates.items():
        if value is None:
            base.pop(key, None)
        elif isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def write_config(updates: dict) -> str:
    """把 updates 深合并进 config.yaml 并写盘，返回文件路径（全局写入口）。"""
    data = dict(load_config())
    _deep_merge(data, updates)
    path = config_path()
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
    # 让下一次读取命中新 mtime
    load_config()
    return path
