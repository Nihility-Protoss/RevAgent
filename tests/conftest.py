import pytest
from tools.entry_store import shutdown_stores


@pytest.fixture(autouse=True)
def _close_entry_stores_after_test():
    yield
    shutdown_stores()
