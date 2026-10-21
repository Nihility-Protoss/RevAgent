import json
import pathlib

import pytest

from tools.blackboard_tools import bb_read_extract, board_base_dir


@pytest.fixture
def board_dir(tmp_path, monkeypatch):
    """在临时目录下搭建黑板并切换 cwd（Windows 下句柄可能未释放）。"""
    monkeypatch.chdir(tmp_path)
    board = tmp_path / board_base_dir() / "test_proj" / "extracts"
    board.mkdir(parents=True)
    return board


def test_bb_read_extract_missing_file(board_dir):
    result = bb_read_extract("strings", "test_proj")
    assert result["status"] == "error"
    assert result["reason"] == "extract_not_found"


def test_bb_read_extract_chunked_functions(board_dir):
    functions = [{"addr": f"0x{i:x}", "name": f"fn_{i}"} for i in range(250)]
    with open(board_dir / "function_index.json", "w", encoding="utf-8") as f:
        json.dump({"chunk_size": 100, "functions": functions}, f)

    page0 = bb_read_extract("function_index", "test_proj", chunk_index=0)
    assert page0["status"] == "success"
    assert len(page0["data"]["functions"]) == 100
    assert page0["data"]["has_more"] is True

    page2 = bb_read_extract("function_index", "test_proj", chunk_index=2)
    assert len(page2["data"]["functions"]) == 50
    assert page2["data"]["has_more"] is False


def test_bb_read_extract_chunked_strings(board_dir):
    by_category = {"url": [f"http://x{i}.example" for i in range(150)]}
    with open(board_dir / "strings.json", "w", encoding="utf-8") as f:
        json.dump({"chunk_size": 100, "by_category": by_category, "by_type": {"x": 1}}, f)

    page0 = bb_read_extract("strings", "test_proj", chunk_index=0)
    assert page0["status"] == "success"
    assert len(page0["data"]["by_category"]["url"]) == 100
    assert page0["data"]["has_more"] is True
    # by_type 全量副本不应进入上下文
    assert "by_type" not in page0["data"]


def test_legacy_blackboard_api_is_not_referenced():
    roots = [pathlib.Path("graph"), pathlib.Path("workers")]
    forbidden = (
        "bb_read_summary", "bb_write_summary", "bb_read_artifact",
        "bb_write_artifact", "bb_list_summaries", "bb_has_artifact", "run_extraction",
    )
    files = [pathlib.Path("tools/blackboard_tools.py")]
    for root in roots:
        files.extend(root.rglob("*.py") if root.is_dir() else [root])
    for path in files:
        text = path.read_text(encoding="utf-8")
        for name in forbidden:
            assert name not in text, f"{path} still references {name}"
