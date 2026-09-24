import os
import json
import tempfile
import shutil
import pytest

from tools.blackboard_tools import board_base_dir
from tools.file_loaders import pre_extract_sample


def test_pre_extract_creates_extracts():
    """预提取应创建全部 extract JSON 文件。
    """
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "data", "input", "module.upx_export_for_ai")
    if not os.path.exists(fixture_dir):
        pytest.skip("Fixture data not found")

    with tempfile.TemporaryDirectory() as tmpdir:
        export_dir = os.path.join(tmpdir, "export")
        shutil.copytree(fixture_dir, export_dir)
        project_name = "test_module"

        result = pre_extract_sample(export_dir, project_name, output_base=tmpdir)

        assert result["status"] == "success"
        extracts_dir = os.path.join(tmpdir, board_base_dir(), project_name, "extracts")
        assert os.path.exists(extracts_dir)
        assert os.path.exists(os.path.join(extracts_dir, "strings_extract.json"))
        assert os.path.exists(os.path.join(extracts_dir, "imports_extract.json"))
        assert os.path.exists(os.path.join(extracts_dir, "exports_extract.json"))
        assert os.path.exists(os.path.join(extracts_dir, "functions_extract.json"))
        assert os.path.exists(os.path.join(extracts_dir, "functions_manifest.json"))


def test_pre_extract_strings_structure():
    """strings_extract.json 必须包含预期的分类。
    """
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "data", "input", "module.upx_export_for_ai")
    if not os.path.exists(fixture_dir):
        pytest.skip("Fixture data not found")

    with tempfile.TemporaryDirectory() as tmpdir:
        export_dir = os.path.join(tmpdir, "export")
        shutil.copytree(fixture_dir, export_dir)

        pre_extract_sample(export_dir, "test", output_base=tmpdir)

        path = os.path.join(tmpdir, board_base_dir(), "test", "extracts", "strings_extract.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "total_count" in data
        assert "by_type" in data
        assert "by_category" in data
        assert "chunks" in data
        assert isinstance(data["chunks"], int)
