"""全局配置：根目录 config.yaml 的统一读写入口。

优先级：config.yaml > 环境变量 > 默认值。

快照语义：进程首次读取 config.yaml 后立即深拷贝一份冻结快照（`_snapshot`），
文件句柄当场关闭；此后所有 `cfg()` / `cfg_int()` / `cfg_bool()` 只查快照，
不再 stat 或重读文件。这样并行运行多个分析进程时，任一进程改写共享的
config.yaml 都不会影响正在运行的进程（各自持有启动时的配置视图）。

需要重新读盘时（测试 chdir 到临时目录、进程内改了配置文件后想立刻生效），
显式调用 `reset_config_cache()` 清空快照，下次读取会生成新快照。

API_KEY 等机密仍放 .env，config.yaml 只记录用哪个环境变量（`llm.api_key_env`）。
"""
import copy
import os
from typing import Any, Optional

import yaml

CONFIG_FILENAME = "config.yaml"

_snapshot: Optional[dict] = None
_cache: dict = {}
_cache_key: Optional[tuple] = None


def config_path() -> str:
    """当前工作目录下的 config.yaml 路径。"""
    return os.path.join(os.getcwd(), CONFIG_FILENAME)


def load_config() -> dict:
    """返回配置快照；进程内首次调用时读盘并冻结快照。

    未快照阶段仍按 (路径, mtime) 缓存作为加速手段，但快照一旦生成，
    后续调用直接返回它，不再访问磁盘。
    """
    global _snapshot, _cache, _cache_key
    if _snapshot is not None:
        return _snapshot
    path = config_path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        _cache, _cache_key = {}, None
    else:
        key = (path, mtime)
        if key != _cache_key:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            _cache = data if isinstance(data, dict) else {}
            _cache_key = key
    _snapshot = copy.deepcopy(_cache)
    return _snapshot


def reset_config_cache() -> None:
    """清空快照与 mtime 缓存，下一次读取重新读盘生成新快照（测试/重载逃生门）。"""
    global _snapshot, _cache, _cache_key
    _snapshot = None
    _cache = {}
    _cache_key = None


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
    """把 updates 深合并进 config.yaml 并写盘，返回文件路径（全局写入口）。

    写盘完成后调用 `reset_config_cache()`，使进程内后续读取基于刚写入的
    内容生成新快照（其它已启动的进程仍持有各自的旧快照，不受影响）。
    """
    data = copy.deepcopy(load_config())
    _deep_merge(data, updates)
    path = config_path()
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
    reset_config_cache()
    return path
