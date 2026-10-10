"""金标准对比评测：将 RevAgent 生成的报告与人工金标准报告做覆盖率对比。

用法：
    python -m tools.benchmark \
        --gold <金标准目录或 ALL_IN_ONE.md 路径> \
        --report <RevAgent 生成的 final_report.md> \
        --out <对比报告输出路径.md>

金标准目录/文件**不进 git**，路径一律通过 CLI 传入。

评测维度（均为召回率 recall：金标准中出现的条目，在待评报告中被提及的比例）：
    1. 章节结构   —— 9 章 ALL_IN_ONE 骨架是否齐全
    2. 命令码覆盖 —— 金标准逐命令分析中的命令码（cmd 0xXX）
    3. 关键函数   —— 金标准函数速查表中的地址与重命名
    4. 断点指南   —— P0/P1/P2 断点地址命中
    5. 全局变量   —— g_* 全局变量名
    6. IoC 指标   —— 文件路径 / 注册表路径 / 特征 API
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------- 金标准条目提取 ----------------

# 内存地址（IDA 默认镜像基址风格，如 0x180013D80；兼容其他长度）
_ADDR_RE = re.compile(r"\b0x[0-9A-Fa-f]{6,}\b")
# 命令码（cmd 0x11 / 命令 0x11 / `0x11` 标题形式）
_CMD_RE = re.compile(r"(?:cmd|命令|case|####)\s*`?(0x[0-9A-Fa-f]{2})\b")
# 反引号包裹的 snake_case 重命名函数（如 `command_dispatcher`）
_NAME_RE = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`")
# 全局变量（g_ 前缀）
_GVAR_RE = re.compile(r"\b(g_[a-z0-9_]+)\b")
# 文件路径 / 注册表路径 / Windows API
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s|，。`)]+")
_REG_RE = re.compile(r"HK(?:CU|LM|CR|U|S)\\[^\s|，。`)]+")
# API 候选：首字母大写、长度 ≥4、至少含一个小写字母；
# 之后再按"大写字母 ≥2"过滤，排除 Windows/Loader 等普通单词
_API_RE = re.compile(r"\b(?=[A-Za-z0-9]*[a-z])([A-Z][A-Za-z0-9]{3,})\b")


def _looks_like_api(token: str) -> bool:
    """判断标识符是否像 Windows API（混合大小写且大写 ≥2，如 MoveFileExW）。"""
    return sum(1 for c in token if c.isupper()) >= 2

# 9 章骨架关键词（命中即视为该章存在）
CHAPTER_KEYWORDS: Dict[str, List[str]] = {
    "1_样本概览": ["样本概览"],
    "2_执行流程": ["执行流程"],
    "3_能力矩阵": ["能力矩阵", "驻留", "持久化"],
    "4_函数速查": ["函数速查", "关键函数"],
    "5_断点指南": ["断点"],
    "6_全局变量": ["全局变量"],
    "7_C2提取": ["C2", "提取"],
    "8_IoC": ["IoC", "指标"],
    "9_调试注意": ["调试注意", "反调试"],
}

# 金标准中出现的、但在待评报告中匹配意义不大的通用名（误报过滤）
_NAME_STOPWORDS = {
    "file_loader", "string_analysis", "function_index", "sample_project",
}


def _read_gold_texts(gold: Path) -> str:
    """读取金标准文本：目录时合并 ALL_IN_ONE.md 与 AGENT_*.md，单文件时只读该文件。"""
    if gold.is_dir():
        parts = []
        for pat in ("ALL_IN_ONE.md", "AGENT_*.md"):
            for f in sorted(gold.glob(pat)):
                parts.append(f.read_text(encoding="utf-8", errors="replace"))
        if not parts:
            raise RuntimeError(f"金标准目录中未找到 ALL_IN_ONE.md / AGENT_*.md：{gold}")
        return "\n\n".join(parts)
    return gold.read_text(encoding="utf-8", errors="replace")


def extract_gold_items(gold_text: str) -> Dict[str, Set[str]]:
    """从金标准文本提取各维度条目集合。"""
    cmd_codes = {c.upper() for c in _CMD_RE.findall(gold_text)}
    addresses = {a.upper() for a in _ADDR_RE.findall(gold_text)}
    names = {n for n in _NAME_RE.findall(gold_text) if n not in _NAME_STOPWORDS}
    gvars = set(_GVAR_RE.findall(gold_text))
    iocs = (
        {p.rstrip("\\") for p in _PATH_RE.findall(gold_text)}
        | {r.rstrip("\\") for r in _REG_RE.findall(gold_text)}
        | {a for a in _API_RE.findall(gold_text) if _looks_like_api(a)}
    )
    return {
        "cmd_codes": cmd_codes,
        "addresses": addresses,
        "names": names,
        "gvars": gvars,
        "iocs": iocs,
    }


# ---------------- 覆盖率计算 ----------------


def _recall(gold_items: Set[str], report_text: str) -> Dict:
    """计算单个维度的召回率；返回命中/缺失清单与比率。"""
    if not gold_items:
        return {"total": 0, "hit": 0, "recall": None, "missing": []}
    upper = report_text.upper()
    hit, missing = [], []
    for item in sorted(gold_items):
        (hit if item.upper() in upper else missing).append(item)
    return {
        "total": len(gold_items),
        "hit": len(hit),
        "recall": round(len(hit) / len(gold_items), 4),
        "missing": missing,
    }


def compare(gold_text: str, report_text: str) -> Dict:
    """执行全维度对比，返回结构化结果。"""
    gold_items = extract_gold_items(gold_text)
    result: Dict[str, Dict] = {}

    # 章节结构
    chapters_hit = [
        name
        for name, kws in CHAPTER_KEYWORDS.items()
        if all(kw in report_text for kw in kws)
    ]
    result["chapters"] = {
        "total": len(CHAPTER_KEYWORDS),
        "hit": len(chapters_hit),
        "recall": round(len(chapters_hit) / len(CHAPTER_KEYWORDS), 4),
        "missing": [n for n in CHAPTER_KEYWORDS if n not in chapters_hit],
    }

    result["cmd_codes"] = _recall(gold_items["cmd_codes"], report_text)
    result["key_addresses"] = _recall(gold_items["addresses"], report_text)
    result["func_names"] = _recall(gold_items["names"], report_text)
    result["gvars"] = _recall(gold_items["gvars"], report_text)
    result["iocs"] = _recall(gold_items["iocs"], report_text)

    scored = [v["recall"] for v in result.values() if v["recall"] is not None]
    result["overall"] = {
        "recall": round(sum(scored) / len(scored), 4) if scored else None
    }
    return result


# ---------------- 报告渲染 ----------------

_DIM_TITLES = {
    "chapters": "章节结构",
    "cmd_codes": "命令码覆盖",
    "key_addresses": "关键地址（函数/断点/变量）",
    "func_names": "重命名函数",
    "gvars": "全局变量",
    "iocs": "IoC 指标",
}


def render_markdown(result: Dict, gold_path: str, report_path: str) -> str:
    """渲染人类可读的对比报告（Markdown）。"""
    lines = [
        "# RevAgent 报告 × 金标准 对比评测",
        "",
        f"- 金标准：`{gold_path}`",
        f"- 待评报告：`{report_path}`",
        f"- **综合召回率：{result['overall']['recall']}**",
        "",
        "| 维度 | 命中 | 总数 | 召回率 |",
        "|------|------|------|--------|",
    ]
    for key, title in _DIM_TITLES.items():
        v = result[key]
        recall = "—" if v["recall"] is None else f"{v['recall']:.1%}"
        lines.append(f"| {title} | {v['hit']} | {v['total']} | {recall} |")
    lines.append("")
    for key, title in _DIM_TITLES.items():
        missing = result[key]["missing"]
        if not missing:
            continue
        lines.append(f"## 缺失：{title}（{len(missing)} 项）")
        lines.append("")
        show = missing if key == "chapters" else [f"`{m}`" for m in missing[:50]]
        lines.append("、".join(show))
        if len(missing) > 50 and key != "chapters":
            lines.append(f"\n\n…另有 {len(missing) - 50} 项未列出")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="RevAgent 报告 × 金标准 对比评测")
    parser.add_argument("--gold", required=True, help="金标准目录或 ALL_IN_ONE.md 路径")
    parser.add_argument("--report", required=True, help="RevAgent 生成的 final_report.md")
    parser.add_argument("--out", default=None, help="对比报告输出路径（缺省只打印 stdout）")
    parser.add_argument("--json", default=None, help="可选：结构化结果 JSON 输出路径")
    args = parser.parse_args()

    gold_path = Path(args.gold)
    report_path = Path(args.report)
    if not report_path.exists():
        raise SystemExit(f"待评报告不存在：{report_path}")

    result = compare(
        _read_gold_texts(gold_path),
        report_path.read_text(encoding="utf-8", errors="replace"),
    )
    md = render_markdown(result, str(gold_path), str(report_path))
    print(md)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
