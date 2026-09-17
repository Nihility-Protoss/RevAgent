# Malware Analysis ADK Agent — Architecture Guide

> **版本**: 2.0 (MVP)  
> **ADK 版本**: 2.1.0+  
> **工作流引擎**: `google.adk.workflow.Workflow`  
> **适用范围**: 基于 IDA 无 MCP 导出文件的 Windows PE 恶意样本静态分析

---

## 1. 概述

本 Agent 是一个基于 Google ADK 的恶意样本深度分析系统。核心设计原则是：

1. **静态分析为主**：输入数据来自分析师人工导出的 IDA 反编译/反汇编文件，不直接解析原始二进制
2. **分阶段递进**：Phase 0 快速定性 → Phase 1 行为定型 → Phase 2 调度审查
3. **人在回路（HITL）**：关键决策点触发人工审查，分析结果不自动执行
4. **Token 可观测**：完整统计各阶段 LLM Token 消耗，支持成本控制和优化

---

## 2. 整体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     malware_analysis_workflow (Workflow)                 │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Phase 0: Triage Swarm (并行)                                     │   │
│  │                                                                  │   │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │   │
│  │   │   String     │  │     API      │  │   Export     │        │   │
│  │   │  Artifact    │  │  Behavior    │  │  Interface   │        │   │
│  │   │  Analyst     │  │  Profiler    │  │  Analyzer    │        │   │
│  │   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        │   │
│  │          │                 │                 │                 │   │
│  │          └─────────────────┴─────────────────┘                 │   │
│  │                            │                                    │   │
│  │              output_key: string_analysis / api_behavior_analysis │   │
│  │                         / export_interface_analysis              │   │
│  └────────────────────────────┬───────────────────────────────────┘   │
│                               │ (fan-in: 等待3个Worker全部完成)        │
│  ┌────────────────────────────┼───────────────────────────────────┐   │
│  │  Phase 1: Deep Swarm (并行)│                                    │   │
│  │                            │                                    │   │
│  │   ┌──────────────────┐    │    ┌──────────────────┐           │   │
│  │   │  Behavior Profile│◄───┴───►│ Function Boundary │           │   │
│  │   │   Synthesizer    │         │    Detector       │           │   │
│  │   └──────┬───────────┘         └────────┬──────────┘           │   │
│  │          │                                │                      │   │
│  │          └────────────────────────────────┘                      │   │
│  │                            │                                     │   │
│  │              output_key: behavior_profile /                      │   │
│  │                         function_boundary_analysis               │   │
│  └────────────────────────────┬───────────────────────────────────┘   │
│                               │ (fan-in: 等待2个Worker全部完成)        │
│  ┌────────────────────────────┼───────────────────────────────────┐   │
│  │  Phase 2: Scheduler + HITL │                                    │   │
│  │                            │                                    │   │
│  │   ┌────────────────────────┘                                    │   │
│  │   │  Scheduler Agent                                              │   │
│  │   │  - 读取5个Worker输出                                         │   │
│  │   │  - 整合摘要 → output_key: scheduler_decision                │   │
│  │   │  - after_agent_callback → 触发人工审查暂停                  │   │
│  │   └──────────────────────────────────────────────────────────┘   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Workflow 编排说明

使用 `google.adk.workflow.Workflow` 的元组链式语法定义图边（edges）：

```python
from google.adk.workflow._base_node import START
from google.adk.workflow._workflow import Workflow

root_workflow = Workflow(
    name="malware_analysis_workflow",
    edges=[
        # Phase 0: START → 3 workers (fan-out, 并行)
        (START, (string_artifact_analyst, api_behavior_profiler, export_interface_analyzer)),
        # Phase 1: 3 workers → 2 workers (fan-in + fan-out, 等待Phase0完成后并行)
        ((string_artifact_analyst, api_behavior_profiler, export_interface_analyzer),
         (behavior_profile_synthesizer, function_boundary_detector)),
        # Phase 2: 2 workers → scheduler (fan-in, 等待Phase1完成后顺序)
        ((behavior_profile_synthesizer, function_boundary_detector), scheduler_agent),
    ]
)
```

**关键概念**：
- **Fan-out**: `(START, (A, B, C))` — START 同时触发 A/B/C 三个节点并行
- **Fan-in**: `((A, B, C), D)` — D 等待 A/B/C 全部完成后才触发
- 弃用的 `ParallelAgent` / `SequentialAgent` 已完全被 `Workflow` 替代

---

## 3. Worker Agent 设计

每个 Worker 使用统一的**五段式提示词结构**：
1. **角色定义段**：专业身份和分析范围
2. **输入数据说明段**：从 FunctionTool 获取的结构化数据
3. **分析维度段**：检查指标和关注要点
4. **输出格式约束段**：强制 JSON 输出
5. **置信度与误差控制段**：high/medium/low 标准，禁止幻觉

### 3.1 Phase 0: Triage Swarm（快速定性）

#### String Artifact Analyst
- **职责**: 分析 `strings.txt`，提取数据文件名、PDB路径、密钥、URL、注册表路径、互斥体名、伪装信息等
- **输入**: `load_strings` 返回的结构化字符串数据
- **输出键**: `string_analysis`
- **核心原则**: strings.txt 优先级高于 imports.txt（API 哈希可绕过 IAT，字符串无法隐藏）

#### API Behavior Profiler
- **职责**: 分析 `imports.txt`，识别 API 组合、MITRE 映射、DLL依赖、API哈希动态解析迹象
- **输入**: `load_imports` + `load_strings` 辅助
- **输出键**: `api_behavior_analysis`
- **关键分析**: 进程注入、文件加载型、持久化、网络通信、信息窃取、反分析、UAC绕过、凭据窃取

#### Export & Interface Analyzer
- **职责**: 分析 `exports.txt`，建立 ordinal 映射、判定加载方式、识别命令接口
- **输入**: `load_exports` + `load_function_index`
- **输出键**: `export_interface_analysis`
- **加载方式判定**: 标准插件型 / 反射加载 / 侧加载 / 宿主Patch

### 3.2 Phase 1: Deep Swarm（行为定型+函数筛选）

#### Behavior Profile & Architecture Synthesizer
- **职责**: 综合 Phase 0 输出（或原始数据），定型 RAT/Stealer/Loader/Backdoor，推断持久化/窃取/反调试/断点矩阵
- **输入**: `load_strings` + `load_imports` + `load_exports`（优先读取 Phase 0 Worker 的 state 输出）
- **输出键**: `behavior_profile`
- **关键产出**: P0/P1/P2 断点矩阵建议、8步分析 checklist 完成状态

#### Function Boundary Detector
- **职责**: 评估 `function_index.txt`，排序候选函数，排除 thunk，推荐 Top 20
- **输入**: `load_function_index` + `load_exports` + `load_strings`
- **输出键**: `function_boundary_analysis`
- **排序维度**: xrefs 调用频率、thunk 排除、函数大小、入口点 proximity、命名暗示、导出函数优先

### 3.3 Phase 2: Scheduler + HITL

#### Scheduler Agent
- **职责**: 中央协调器，读取 5 个 Worker 输出，整合摘要，触发人工审查
- **输出键**: `scheduler_decision`
- **回调**: `after_agent_callback=human_review_callback`
- **规则**: 只做数据路由和状态管理，不做样本分析推理

#### Human Review Callback
- **触发时机**: Phase 2 完成后（`analysis_phase == "initial_complete"`）
- **审查内容**: 行为定型结论、高风险发现摘要、Top 20 候选函数、Checklist 完成状态
- **输出状态**: `execution_status = "WAITING_FOR_APPROVAL"`
- **回复格式**: `CONFIRM` 或 `MODIFY [具体修正内容]`

### 3.4 知识指南注入（Phase 0→1 门控）

- **来源**: Phase 0 字符串分析输出 `arch_detection`（架构/语言/加载方式）。
- **路由**: orchestrator 的 `resolve_active_guides` 读取 `summary/strings_summary.json` 的 `arch_detection`，匹配 `workers/knowledge/` 知识库，将激活的指南元数据写入 `meta/active_guides.json`。
- **消费**: Phase 1 经 `load_arch_guide("__active__")` 按需加载激活指南并注入 prompt；Phase 3 将同一批指南注入动态 Analyzer prompt。
- **默认回退**: `strings_summary` 或 `arch_detection` 缺失时回退到默认指南 `windows_pe`。

---

## 4. FunctionTool 清单

| 工具名 | 功能 | 输入 | Worker 使用者 |
|-------|------|------|-------------|
| `load_strings` | 加载并分类 `strings.txt` | 文件路径 | String Analyst, API Profiler, Behavior Synthesizer, Function Detector |
| `load_exports` | 加载 `exports.txt`，构建 ordinal 映射 | 文件路径 | Export Analyzer, Behavior Synthesizer, Function Detector |
| `load_imports` | 加载 `imports.txt`，API 分类 | 文件路径 | API Profiler, Behavior Synthesizer |
| `load_function_index` | 加载 `function_index.txt` | 文件路径 | Export Analyzer, Function Detector |
| `load_pe_info` | 加载预生成的 `pe_info.json` | 文件路径 | —（预留） |
| `detect_sample_type` | 基于导出文件判断样本类型 | 导出目录路径 | —（预留） |
| `calculate_entropy` | 计算 Shannon 熵 | 字节块 | —（预留） |

### 4.1 输入数据规范

Agent 接收一个**样本导出目录**作为输入：

```
{sample_export_dir}/
├── strings.txt              # IDA 导出的字符串表
├── exports.txt              # IDA 导出的导出函数表
├── imports.txt              # IDA 导出的导入函数表
├── function_index.txt       # IDA 导出的函数索引（地址、名称、大小、xrefs）
├── decompile/               # 反编译结果 (*.c)
├── disassembly/             # 反汇编结果 (*.asm)
├── memory/                  # 内存 dump（可选）
└── pe_info.json             # PE 头部/段表信息（由辅助脚本预提取，可选）
```

> **注**: `pe_info.json` 可由独立脚本（使用 `pefile` 库）从原始样本预生成，不作为 ADK 工作流依赖。

---

## 5. 状态管理

### 5.1 Session State 键规范

**系统级状态键**：

| 键名 | 类型 | 写入者 | 读取者 |
|------|------|--------|--------|
| `sample_project_name` | str | Runner 初始化 | Token Report |
| `sample_export_dir` | str | Runner 初始化 | FunctionTool |
| `sample_type` | str | Runner 初始化 | — |
| `analysis_phase` | str | 调度者 | 回调函数 |
| `execution_status` | str | 调度者/回调 | 外部接口 |
| `pending_human_review` | dict | 回调 | 外部审查接口 |

**Worker 输出键**：

| 键名 | 写入 Worker | 读取者 |
|------|-----------|--------|
| `string_analysis` | String Artifact Analyst | 调度者 |
| `api_behavior_analysis` | API Behavior Profiler | 调度者 |
| `export_interface_analysis` | Export Interface Analyzer | 调度者 |
| `behavior_profile` | Behavior Profile Synthesizer | 调度者 |
| `function_boundary_analysis` | Function Boundary Detector | 调度者 |
| `scheduler_decision` | Scheduler Agent | 外部接口 |

### 5.2 Token 统计

`run_analysis()` 返回 `AnalysisTokenReport` 对象，包含：

- **全局限度**: 总 LLM 调用次数、总 prompt/candidate/total tokens
- **阶段细分**: 每个 Worker/节点的 token 消耗（按 `event.nodeInfo.node_name` 聚合）
- **序列化**: `to_dict()` 输出 JSON 可序列化格式

**使用示例**：

```python
runner, session_service, events, token_report = run_analysis(
    sample_export_dir="/path/to/export",
    sample_project_name="sample_001"
)

print(token_report.total_tokens)        # 64,170
print(token_report.stages["scheduler"]) # StageTokenStats(...)
print(str(token_report))                # 人类可读报告
```

---

## 6. 目录结构

```
multi_agent_adk/
├── agent.py                          # 瘦入口：运行时入口（run_analysis / run_analysis_with_blackboard）+ root_agent 再导出
├── pyproject.toml                    # 项目依赖
├── .env                              # MOONSHOT_API_KEY（及 MODEL/API_KEY/BASE_URL，代码实际读取）
├── ARCHITECTURE.md                   # 本文件 — 架构指南
├── tools/                            # FunctionTool 实现
│   ├── __init__.py
│   ├── file_loaders.py               # IDA 导出文件加载工具（含 Phase -1 预提取）
│   ├── pe_utils.py                   # PE 辅助工具（熵值计算等）
│   ├── blackboard_tools.py           # 黑板读写、checkpoint、日志、函数反编译片段加载
│   ├── state_utils.py                # Session State 解析辅助（coerce_state_dict / extract_arch_detection）
│   └── token_stats.py                # Token 统计（StageTokenStats / AnalysisTokenReport）
├── workers/                          # Worker Agent 定义
│   ├── __init__.py
│   ├── shared_prompts.py             # 五段式提示词模板
│   ├── extractor.py                  # 摘要提取器 Agent（artifact → ≤1500 tokens summary）
│   ├── knowledge/                    # 专项分析方法论知识库（arch_detection 路由 + load_arch_guide 工具）
│   ├── orchestrator.py               # Workflow 组装 + 各阶段编排（原 agent.py 编排主体）
│   ├── phase0/                       # Phase 0: 快速定性
│   │   ├── __init__.py
│   │   ├── string_artifact_analyst.py
│   │   ├── api_behavior_profiler.py
│   │   └── export_interface_analyzer.py
│   ├── phase1/                       # Phase 1: 行为定型+函数筛选
│   │   ├── __init__.py
│   │   ├── behavior_profile_synthesizer.py
│   │   └── function_boundary_detector.py
│   ├── phase3/                       # Phase 3: 函数级深度分析（动态循环）
│   │   ├── __init__.py
│   │   └── function_deep_analyzer.py
│   └── phase4/                       # Phase 4: 综合报告
│       ├── __init__.py
│       └── synthesis_agent.py
├── callbacks/                        # 回调函数
│   ├── __init__.py
│   └── human_review.py               # 人工审查回调
└── tests/                            # 测试
    ├── __init__.py
    ├── test_tools.py
    ├── test_workers.py
    ├── test_integration.py
    ├── test_blackboard_tools.py
    ├── test_extractor.py
    ├── test_fault_tolerance.py
    ├── test_pre_extract.py
    ├── test_phase3.py
    ├── test_phase4.py
    ├── test_knowledge.py
    └── test_state_coercion.py
```

---

## 7. 扩展路线图

### P1 — 高优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **技能知识精修** | 将 `arch_windows_pe.md` 中的专项分析知识（DLL插件型/文件加载型/API哈希动态解析等）精修进各 Worker 提示词 | `workers/phase0/*.py`, `workers/phase1/*.py` |
| **函数级深度分析 Worker** ✅ 已落地 | 对 `function_boundary_analysis` 推荐的 Top N 候选函数进行逐函数汇编级分析 | 已实现于 `workers/phase3/function_deep_analyzer.py` |
| **动态 Worker 构建** ✅ 已落地 | 根据人工确认的函数数量，动态创建函数分析 Worker 实例 | 已实现于 `workers/orchestrator.py`（Phase 3 动态循环） |
| **Worker output_schema 化** | 为 Worker 声明 `output_schema`，根治 state 中以 JSON 字符串存储的结构化输出 | `workers/phase*/**.py`、`tools/state_utils.py` |

### P2 — 中优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **验证 Worker** | 对 high 置信度发现自动触发验证，检测幻觉和过度推断 | 新增 `workers/verification_agent.py` |
| **ALL_IN_ONE 生成 Worker** | 整合所有分析结论，生成面向动态调试的综合参考手册 | 新增 `workers/report_generator.py` |
| **归档输出** | Worker 输出按 `docs/{项目名}/AGENT_XX_{主题}.md` 规范落盘 | 新增 `tools/archiver.py` |
| **LNK 可选子 Agent** | 当检测到 LNK 样本时，动态加载 LNK Metadata Analyzer | 新增 `workers/optional/lnk_analyzer.py` |

### P3 — 低优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **多样本关联分析** | 支持同源样本对比（Loader→Downloader→Payload 攻击链） | 新增 `workers/multi_sample/comparison_agent.py` |
| **Web UI 审查界面** | 将 `pending_human_review` 渲染为可视化审查面板 | 独立前端项目 |
| **PE 头部/段表分析** | 当提供原始样本时，增加 PE Header 和 Section Analyzer Worker | 新增 `workers/phase0/pe_header_analyzer.py`, `workers/phase0/section_analyzer.py` |

---

## 8. 依赖

```toml
[project]
name = "multi-agent-adk"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "google-adk>=0.2.0",
    "pydantic>=2.0",
    "python-dotenv>=1.0",
]
```

> `pefile`、`capstone` 等二进制解析库**不作为 ADK 依赖**。`pe_info.json` 的生成脚本可独立安装这些库运行。

---

## 9. 运行方式

### 9.1 程序化调用

```python
from agent import run_analysis

runner, session_service, events, token_report = run_analysis(
    sample_export_dir="/path/to/ida/export",
    sample_project_name="malware_sample_001",
    sample_type="pe"
)
```

### 9.2 ADK CLI

```bash
# 设置 API Key
export GOOGLE_API_KEY="your-key"

# 使用 ADK CLI 运行
adk run agent
```

### 9.3 环境要求

- Python 3.10+
- Google API Key（Gemini 模型访问）
- IDA 无 MCP 导出目录（strings.txt, exports.txt, imports.txt, function_index.txt）
