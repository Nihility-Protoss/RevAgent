"""金标准对比评测（tools/benchmark.py）的单元测试。"""
from tools.benchmark import compare, extract_gold_items, render_markdown

# 合成金标准：覆盖六种提取维度
GOLD_TEXT = """
# ALL_IN_ONE.md
## 4. 关键函数速查表
| `0x180013D80` | `dll_initialize` | `ordinal_1` |
| `0x180056920` | `command_dispatcher` | `ordinal_2` |
cmd 0x0D 版本校验；cmd 0x11 反向 Shell；cmd 0x20 浏览器凭证
## 6. 内存中的关键全局变量
| `0x1801A5E18` | `g_main_callback` |
| `0x1801A5C10` | `g_decrypted_string_1` |
## 8. IoC
`C:\\ProgramData\\fbhis`；`HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\`；
`CreateToolhelp32Snapshot` 进程枚举；`MoveFileExW` 持久化
"""

# 命中全部维度的待评报告
FULL_REPORT = """
# 综合参考手册
## 样本概览
## 完整执行流程图
## 全部操作能力矩阵（驻留/持久化）
## 关键函数速查表
0x180013D80 dll_initialize；0x180056920 command_dispatcher
cmd 0x0D、cmd 0x11、cmd 0x20
## 动态分析断点指南
## 内存中的关键全局变量
g_main_callback、g_decrypted_string_1
## C2 / 配置提取方法
## IoC 指标汇总
C:\\ProgramData\\fbhis
HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\
CreateToolhelp32Snapshot、MoveFileExW
## 调试注意事项（反调试对抗）
"""

EMPTY_REPORT = "# 空报告\n没有任何实质内容。"


def test_extract_gold_items_dimensions():
    """金标准条目提取覆盖全部五个维度。"""
    items = extract_gold_items(GOLD_TEXT)
    assert {"0X0D", "0X11", "0X20"} <= items["cmd_codes"]
    assert "0X180013D80" in items["addresses"]
    assert {"dll_initialize", "command_dispatcher"} <= items["names"]
    assert {"g_main_callback", "g_decrypted_string_1"} <= items["gvars"]
    assert any("fbhis" in ioc for ioc in items["iocs"])
    assert "CreateToolhelp32Snapshot" in items["iocs"]


def test_compare_full_report_high_recall():
    """全量报告：章节结构满分，各维度召回率接近 1。"""
    result = compare(GOLD_TEXT, FULL_REPORT)
    assert result["chapters"]["recall"] == 1.0
    assert result["cmd_codes"]["recall"] == 1.0
    assert result["gvars"]["recall"] == 1.0
    assert result["overall"]["recall"] >= 0.8


def test_compare_empty_report_low_recall():
    """空报告：命令码/全局变量等维度召回率为 0。"""
    result = compare(GOLD_TEXT, EMPTY_REPORT)
    assert result["cmd_codes"]["recall"] == 0.0
    assert result["gvars"]["recall"] == 0.0
    assert result["overall"]["recall"] < 0.2


def test_render_markdown_contains_overall_and_missing():
    """渲染输出包含综合召回率与缺失清单。"""
    result = compare(GOLD_TEXT, EMPTY_REPORT)
    md = render_markdown(result, "gold_dir", "report.md")
    assert "综合召回率" in md
    assert "缺失：命令码覆盖" in md
    assert "gold_dir" in md
