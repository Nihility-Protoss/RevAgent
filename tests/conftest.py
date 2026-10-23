import pytest
from tools.entry_store import shutdown_stores


@pytest.fixture(autouse=True)
def _reset_config_snapshot():
    """每个用例前后清空 config.py 快照。

    config 快照在进程内首次读取后即冻结，而测试用例普遍 chdir 到临时目录
    并按需写 config.yaml，必须显式重置才能读到当前目录的配置。
    """
    from config import reset_config_cache

    reset_config_cache()
    yield
    reset_config_cache()


@pytest.fixture(autouse=True)
def _close_entry_stores_after_test():
    yield
    shutdown_stores()
