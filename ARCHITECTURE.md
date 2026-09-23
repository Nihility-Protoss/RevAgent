# RevAgent — Architecture Guide

> **版本**: 3.0 (LangGraph 迁移版)  
> **框架**: LangGraph 1.x `StateGraph`（`langgraph>=1.0`）  
> **适用范围**: 基于 IDA 无 MCP 导出文件的 Windows PE 恶意样本静态分析  
> **历史**: 本项目原基于 Google ADK（`google.adk.workflow.Workflow`），已完成迁移至 LangGraph，迁移方案见 `docs/RevAgent_LangGraph迁移方案.md`。

---

## 1. 概述

本 Agent 是一个基于 LangGraph 的恶意样本深度分析系统。核心设计原则是：

1. **静态分析为主**：输入数据来自分析师人工导出的 IDA 反编译/反汇编文件，不直接解析原始二进制
2. **分阶段递进**：Phase -1 预提取 → Phase 0 快速定性 → Phase 1 行为定型 → Phase 2 调度审查 → Phase 3 函数级深度分析 → Phase 4 综合报告
3. **人在回路（HITL）**：Phase 2 结束后经 `approval_gate` 节点暂停，等待人工审查后才继续 Phase 3
4. **Token 可观测**：完整统计各阶段 LLM Token 消耗，支持成本控制和优化

---

## 2. 整体架构

```
START
  │
  ▼
pre_extract（Phase -1 预提取；resume 且黑板已有 checkpoint 时跳过）
  │
  ▼
Phase 0: Triage Swarm（并行扇出，一条出边自动并行）
  ┌──────────────────┬──────────────────┬──────────────────┐
  ▼                  ▼                  ▼
string_artifact_  api_behavior_     export_interface_
analyst           profiler          analyzer
  │                  │                  │
  └──────────────────┼──────────────────┘
                     ▼
resolve_guides（知识路由：arch_detection → meta/active_guides.json）
                     │
                     ▼
Phase 1: Deep Swarm（并行扇出）
  ┌──────────────────┴──────────────────┐
  ▼                                     ▼
behavior_profile_              function_boundary_
synthesizer                    detector
  │                                     │
  └──────────────────┬──────────────────┘
                     ▼
scheduler（读取 5 个 summary → scheduler_decision）
                     │
                     ▼
approval_gate（HITL：CLI input()，CONFIRM / MODIFY addr,...；3 次无效默认 CONFIRM）
                     │
                     ▼
phase3_deep_analysis（节点内串行循环：逐函数 llm.ainvoke，bb_has_artifact 幂等跳过，
                     每个函数完成后 bb_checkpoint）
                     │
                     ▼
shard_synthesis（Map：每 5 个可疑函数一片，串行分片为小模型稳定性保留）
                     │
                     ▼
aggregator（Reduce：汇总 shard_reports → summary/p4_final_report）
                     │
                     ▼
END
```

> Phase 3/4 的并行化（LangGraph `Send` 扇出、SqliteSaver 持久化 + `interrupt()` 恢复 HITL）是后续 Step 2/3 的待办，当前为节点内串行实现。

### 2.1 图编排说明

唯一的编排定义处是 `graph.py` 的 `build_graph(llm=None, checkpointer=None)`，使用 `langgraph.graph.StateGraph` 的边定义语法：

```python
from langgraph.graph import END, START, StateGraph

builder = StateGraph(AnalysisState)

# Phase -1
builder.add_node("pre_extract", pre_extract_node)

# Phase 0：3 个 worker 节点（由 WorkerSpec 经 make_worker_node 编译）
for spec in PHASE0_SPECS:
    builder.add_node(spec.name, make_worker_node(spec, llm))

# 边：一条边扇出即自动并行，多入边扇入（全部完成才继续）
builder.add_edge(START, "pre_extract")
for spec in PHASE0_SPECS:
    builder.add_edge("pre_extract", spec.name)
    builder.add_edge(spec.name, "resolve_guides")
# ... Phase 1 扇出 → scheduler → approval_gate → phase3 → shard → aggregator → END

return builder.compile(checkpointer=checkpointer)
```

**关键概念**：
- **Fan-out**: 一个节点的多条出边会同时触发下游节点并行执行
- **Fan-in**: 一个节点的多条入边要求所有上游节点完成后才触发
- `build_graph(llm=fake)` 可注入假模型，供测试离线跑完整图（`graph.ainvoke`）

---

## 3. Worker Agent 设计

Worker 的框架无关定义在 `workers/specs.py`：每个 Worker 是一个 **`WorkerSpec` frozen dataclass**（`name` / `instruction` / `tools` / `output_key` / `output_schema`），由 `graph_nodes.make_worker_node` 编译为 LangGraph 节点函数。节点内通过 `langchain.agents.create_agent` 构建 ReAct Agent（`response_format=output_schema` 结构化输出，失败时回退 `parse_json_loose` 容错解析），完成后在同一节点内调用 `bb_write_artifact` 落盘 artifact 并运行 extractor 提炼 summary。

提示词仍使用统一的**五段式提示词结构**（常量保留在各 `workers/phaseX/*.py` 原模块，文本未改）：
1. **角色定义段**：专业身份和分析范围
2. **输入数据说明段**：从 FunctionTool 获取的结构化数据
3. **分析维度段**：检查指标和关注要点
4. **输出格式约束段**：强制 JSON 输出
5. **置信度与误差控制段**：high/medium/low 标准，禁止幻觉

### 3.1 Phase 0: Triage Swarm（快速定性）

| Worker | 职责 | 输出键（state 字段） | 最小工具集 |
|-------|------|--------------------|-----------|
| `string_artifact_analyst` | 分析 `strings.txt`，提取数据文件名、PDB路径、密钥、URL、注册表路径、互斥体名、伪装信息等；含 `arch_detection` 子结构 | `string_analysis` | `bb_read_extract`, `load_strings` |
| `api_behavior_profiler` | 分析 `imports.txt`，识别 API 组合、MITRE 映射、DLL依赖、API哈希动态解析迹象 | `api_behavior_analysis` | `bb_read_extract`, `load_imports`, `load_strings` |
| `export_interface_analyzer` | 分析 `exports.txt`，建立 ordinal 映射、判定加载方式、识别命令接口 | `export_interface_analysis` | `bb_read_extract`, `load_exports`, `load_function_index` |

### 3.2 Phase 1: Deep Swarm（行为定型+函数筛选）

| Worker | 职责 | 输出键（state 字段） | 最小工具集 |
|-------|------|--------------------|-----------|
| `behavior_profile_synthesizer` | 综合 Phase 0 摘要，定型 RAT/Stealer/Loader/Backdoor，推断持久化/窃取/反调试/断点矩阵 | `behavior_profile` | `bb_read_summary` |
| `function_boundary_detector` | 评估 `function_index.txt`，排序候选函数，排除 thunk，推荐 Top 20 | `function_boundary_analysis` | `bb_read_extract`, `load_function_index`, `load_exports`, `load_arch_guide` |

- **`output_schema` 化**：`string_analysis` 与 `function_boundary_analysis` 已声明 Pydantic 模型（`state.py` 的 `StringAnalysis` / `FunctionBoundaryAnalysis`），根治了 JSON 字符串状态问题；其余 Worker 暂为自由 dict。
- **行为定型关键产出**: P0/P1/P2 断点矩阵建议、8步分析 checklist 完成状态
- **函数排序维度**: xrefs 调用频率、thunk 排除、函数大小、入口点 proximity、命名暗示、导出函数优先

### 3.3 Phase 2: Scheduler + HITL

#### Scheduler Agent
- **职责**: 中央协调器，读取 5 个 summary，整合摘要，输出决策
- **定义**: `workers/phase2/scheduler.py` 的 `SCHEDULER_INSTRUCTION`，`workers/specs.py` 的 `scheduler` spec
- **输出键**: `scheduler_decision`
- **规则**: 只做数据路由和状态管理，不做样本分析推理

#### Human Review Gate（approval_gate）

- **位置**: `graph_nodes.py` 的 `approval_gate_node` 节点（Phase 2→3 之间）
- **触发时机**: Scheduler 完成后
- **交互方式**: CLI `input()` 逐行读取人工回复（`prompt_human` 为模块级函数，便于测试 monkeypatch）；LangGraph `interrupt()` 化留待 Step 2
- **审查内容**: 行为定型结论、高风险字符串/API 指标计数、Top 20 候选函数
- **回复协议**:
  - `CONFIRM` — 同意继续，使用推荐候选函数（`analysis_priority >= 7` 的 Top 20）
  - `MODIFY <addr1>,<addr2>,...` — 指定要分析的函数地址列表，逗号分隔
  - 连续 3 次无法识别的回复后默认按 CONFIRM 放行
- **写入 state**: `phase2_human_decision`（str）、`human_approved_functions`（list[str]，MODIFY 时）

### 3.4 知识指南注入（Phase 0→1 门控）

- **来源**: Phase 0 字符串分析输出 `arch_detection`（架构/语言/加载方式）。
- **路由**: `graph_nodes.resolve_guides_node` / `resolve_active_guides` 读取图状态中 `string_analysis.arch_detection`，匹配 `workers/knowledge/` 知识库，将激活的指南元数据写入 `meta/active_guides.json`。
- **消费**: Phase 1 经 `load_arch_guide("__active__")` 按需加载激活指南并注入 prompt；Phase 3 由 `_load_active_guides_text` 拼接全文注入函数分析 prompt。
- **默认回退**: `arch_detection` 缺失时回退到默认指南 `windows_pe`。

---

## 4. FunctionTool 清单

Worker 的工具面从旧的 ALL_TOOLS 全量注入收敛为每个 WorkerSpec 声明的 2–4 个最小工具：

| 工具名 | 功能 | Worker 使用者 |
|-------|------|-------------|
| `load_strings` | 加载并分类 `strings.txt` | String Analyst, API Profiler |
| `load_exports` | 加载 `exports.txt`，构建 ordinal 映射 | Export Analyzer, Function Detector |
| `load_imports` | 加载 `imports.txt`，API 分类 | API Profiler |
| `load_function_index` | 加载 `function_index.txt` | Export Analyzer, Function Detector |
| `bb_read_extract` | 读取黑板 `extracts/` 预提取分片 | 全部 Phase 0/1 Worker |
| `bb_read_summary` | 读取黑板 `summary/` 摘要 | Behavior Synthesizer, Scheduler |
| `load_arch_guide` | 加载知识指南（`load_knowledge` 的别名工具） | Function Detector |
| `load_pe_info` | 加载预生成的 `pe_info.json` | —（预留） |
| `detect_sample_type` | 基于导出文件判断样本类型 | `pre_extract` 节点直接调用（非 Worker 工具） |
| `calculate_entropy` | 计算 Shannon 熵 | —（预留） |

> 黑板写入类工具（`bb_write_artifact` / `bb_write_summary` / `bb_checkpoint` / `bb_log_event` / `load_function_data`）不暴露给 Worker Agent，由节点函数（`make_worker_node` / `make_phase3_node` / Phase 4 节点）在 LLM 调用之外直接调用，负责 artifact/summary 持久化与断点。

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

> **注**: `pe_info.json` 可由独立脚本（使用 `pefile` 库）从原始样本预生成，不作为 LangGraph 流程依赖。

---

## 5. 状态管理

### 5.1 AnalysisState 字段规范

图状态定义在 `state.py` 的 `AnalysisState(TypedDict, total=False)`。只放小结构 + 黑板引用，不放 artifact 原文。

**初始化参数**（由 `main.py` 构造）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `sample_project_name` | str | 项目名（`data/output/` 子目录名） |
| `sample_export_dir` | str | IDA 导出目录路径（默认由 `data/input/` 下的 `*_export_for_ai` 自动解析） |
| `sample_type` | str | 样本类型（永远 auto：由 `pre_extract` 节点调 `detect_sample_type` 判定后写入） |
| `resume` | bool | True 时 pre_extract 节点跳过（黑板已有 checkpoint） |

**Worker 结构化输出**（WorkerSpec `output_key` 同名直译，dict 或 Pydantic model_dump）：

| 字段 | 写入节点 | 读取者 |
|------|---------|--------|
| `string_analysis` | string_artifact_analyst | resolve_guides、approval_gate、Phase 4 |
| `api_behavior_analysis` | api_behavior_profiler | approval_gate、Phase 4 |
| `export_interface_analysis` | export_interface_analyzer | Phase 4 |
| `behavior_profile` | behavior_profile_synthesizer | approval_gate、Phase 4 |
| `function_boundary_analysis` | function_boundary_detector | approval_gate、phase3_deep_analysis |
| `scheduler_decision` | scheduler | 外部接口 |

**HITL / Phase 3/4**：

| 字段 | 类型 | 写入节点 | 说明 |
|------|------|---------|------|
| `phase2_human_decision` | str | approval_gate | `CONFIRM` 或 `MODIFY ...` 原文 |
| `human_approved_functions` | list[str] | approval_gate | MODIFY 指定的函数地址列表 |
| `func_analysis_refs` | `Annotated[list[dict], add]` | phase3_deep_analysis | 逐函数分析结果引用（reducer 聚合） |
| `shard_reports` | `Annotated[list[dict], add]` | shard_synthesis | 分片综合报告（reducer 聚合） |
| `final_report_ref` | str | aggregator | 固定为 `bb://summary/p4_final_report` |

### 5.2 Token 统计

`observability.py` 的 `TokenStatsCallback(BaseCallbackHandler)` 挂在 LangChain callback 上，按 `langgraph_node` metadata 将每次 LLM 调用归并到所属图节点，**覆盖全部阶段（含 Phase 3/4）**。聚合结果为 `tools/token_stats.py` 的 `AnalysisTokenReport`（`add_usage(stage_name, prompt, candidate, total)`，输出格式与旧版 `to_dict()` 兼容）。

`main.run_analysis_with_blackboard()` 返回 `(final_state, token_report)`：

```python
final_state, token_report = await run_analysis_with_blackboard(
    sample_project_name="sample_001",  # 输入自动解析自 data/input/
)

print(token_report.total_tokens)        # 总 token
print(token_report.stages["scheduler"]) # StageTokenStats(...)
print(str(token_report))                # 人类可读报告
```

### 5.3 上下文预算（128k）

所有 agent 的单次 LLM 调用输入上限为 **128k tokens**（`config.yaml` 的 `llm.max_context_tokens`，环境变量 `MAX_CONTEXT_TOKENS` 兜底）：

- **Worker（ReAct 循环）**：`create_agent` 挂 `SummarizationMiddleware`，历史消息估算超过 128k 的 75% 时自动摘要压缩，保留最近 20 条消息。
- **直接 LLM 调用**（extractor / Phase 3 / Phase 4）：统一走 `graph_nodes.invoke_guarded`，调用前 `enforce_context_budget` 估算 token，超限时从最长消息开始头尾保留式截断，截断后仍超限则抛 `RuntimeError`。

---

## 6. 目录结构

```
multi-agent-adk/
├── main.py                           # 运行时入口：CLI 参数解析 + run_analysis_with_blackboard
├── graph.py                          # 唯一编排定义处：build_graph(llm, checkpointer) StateGraph 组装
├── graph_nodes.py                    # 节点工厂与业务节点：make_worker_node / pre_extract /
│                                     #   resolve_guides / approval_gate / phase3 / shard / aggregator
├── state.py                          # AnalysisState(TypedDict) + Pydantic 输出模型
│                                     #   (StringAnalysis / FunctionBoundaryAnalysis / ArchDetection / FuncCandidate)
├── observability.py                  # TokenStatsCallback：按 langgraph_node 聚合 token 用量
├── config.py                         # 全局配置读写入口（config.yaml 加载，CLI > yaml > env > 默认值）
├── config.yaml                       # 全局配置：llm / paths / analysis
├── pyproject.toml                    # 项目依赖 + pytest 配置
├── .env                              # API_KEY（已 gitignore；其余配置在 config.yaml）
├── ARCHITECTURE.md                   # 本文件 — 架构指南
├── tools/                            # FunctionTool 实现
│   ├── file_loaders.py               # IDA 导出文件加载工具（含 Phase -1 预提取）
│   ├── pe_utils.py                   # PE 辅助工具（熵值计算等）
│   ├── blackboard_tools.py           # 黑板读写、checkpoint、日志、函数反编译片段加载
│   └── token_stats.py                # Token 统计（StageTokenStats / AnalysisTokenReport）
├── workers/                          # Worker 定义
│   ├── specs.py                      # WorkerSpec frozen dataclass + 6 个 spec（5 worker + scheduler）
│   ├── shared_prompts.py             # 五段式提示词模板
│   ├── extractor.py                  # 摘要提取 prompt 构建（build_extraction_prompt，节点内单次 llm.ainvoke 调用）
│   ├── knowledge/                    # 专项分析方法论知识库（arch_detection 路由 + load_arch_guide 工具）
│   ├── phase0/                       # Phase 0: 快速定性（提示词常量）
│   │   ├── string_artifact_analyst.py
│   │   ├── api_behavior_profiler.py
│   │   └── export_interface_analyzer.py
│   ├── phase1/                       # Phase 1: 行为定型+函数筛选（提示词常量）
│   │   ├── behavior_profile_synthesizer.py
│   │   └── function_boundary_detector.py
│   ├── phase2/
│   │   └── scheduler.py              # Phase 2 调度器提示词
│   ├── phase3/
│   │   └── function_deep_analyzer.py # Phase 3 函数级深度分析 prompt 构建
│   └── phase4/
│       └── synthesis_agent.py        # Phase 4 分片综合 / 聚合 prompt
├── docs/
│   ├── RevAgent_LangGraph迁移方案.md  # ADK → LangGraph 迁移方案
│   └── architecture/                 # 架构图示（HTML/PNG，历史产物）
├── data/
│   ├── input/                        # 输入：放置 *_export_for_ai 的 IDA 导出目录（自动发现）
│   │   └── module.upx_export_for_ai/ # 示例 fixture
│   └── output/                       # 输出（黑板）：{project_name}/{extracts,artifacts,summary,meta}
└── tests/                            # 测试（编排层通过假模型注入 + graph.ainvoke 离线运行）
```

---

## 7. 扩展路线图

### P1 — 高优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **技能知识精修** | 将 `arch_windows_pe.md` 中的专项分析知识（DLL插件型/文件加载型/API哈希动态解析等）精修进各 Worker 提示词 | `workers/phase0/*.py`, `workers/phase1/*.py` |
| **函数级深度分析** ✅ 已落地 | 对候选函数进行逐函数汇编级分析 | `graph_nodes.make_phase3_node`（节点内串行循环） |
| **Worker output_schema 化** ✅ 已落地 | WorkerSpec 声明 `output_schema`（Pydantic），根治 JSON 字符串状态 | `workers/specs.py`、`state.py`（`StringAnalysis` / `FunctionBoundaryAnalysis`） |
| **Phase 3 并行扇出** | 用 LangGraph `Send` 将逐函数分析扇出为真并行 | `graph.py` + `graph_nodes.py`（Step 3 待办） |
| **SqliteSaver + interrupt()** | checkpointer 持久化图状态，HITL 用 `interrupt()` 恢复而非 CLI 阻塞 | `graph.py`、`main.py`（Step 2 待办） |

### P2 — 中优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **验证 Worker** | 对 high 置信度发现自动触发验证，检测幻觉和过度推断 | 新增 `workers/phase3/verification_agent.py` + spec |
| **ALL_IN_ONE 生成 Worker** | 整合所有分析结论，生成面向动态调试的综合参考手册 | 新增 `workers/phase4/report_generator.py` |
| **归档输出** | Worker 输出按 `docs/{项目名}/AGENT_XX_{主题}.md` 规范落盘 | 新增 `tools/archiver.py` |
| **LNK 可选子 Agent** | 当检测到 LNK 样本时，动态加载 LNK Metadata Analyzer | 新增 `workers/optional/lnk_analyzer.py` + `detect_sample_type` |

### P3 — 低优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **多样本关联分析** | 支持同源样本对比（Loader→Downloader→Payload 攻击链） | 新增 `workers/multi_sample/comparison_agent.py` |
| **Web UI 审查界面** | 将审批门渲染为可视化审查面板（配合 interrupt + checkpointer） | 独立前端项目 |
| **PE 头部/段表分析** | 当提供原始样本时，增加 PE Header 和 Section Analyzer Worker | 新增 `workers/phase0/pe_header_analyzer.py`, `workers/phase0/section_analyzer.py` |

---

## 8. 依赖

```toml
[project]
name = "multi-agent-adk"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "langgraph>=1.0",
    "langchain>=1.0",
    "langchain-openai>=1.0",
    "pydantic>=2.0",
    "python-dotenv>=1.0",
    "pyyaml>=6.0",
]
```

> `pefile`、`capstone` 等二进制解析库**不作为项目依赖**。`pe_info.json` 的生成脚本可独立安装这些库运行。

---

## 9. 运行方式

### 9.1 CLI

```bash
# API_KEY 写入 .env；模型/路径/分析默认值在根目录 config.yaml
python main.py \
    -p malware_sample_001      # --project-name：data/output/ 子目录名
    # -i module.upx            # --input-name：可选，指定 data/input/ 下的导出目录（可省略 _export_for_ai 后缀）
    # -r                       # --resume：可选，断点续跑（跳过 Phase -1）
```

配置优先级：**CLI 参数 > `config.yaml` > 环境变量 > 默认值**。输入目录解析规则：显式 `-i` > project-name 前缀匹配 > 唯一候选自动选用；多个候选且无法确定时报错并列出候选。`config.yaml` 配好 `analysis.project_name` 后可无参运行。样本类型永远 auto，由 `pre_extract` 节点调用 `detect_sample_type` 判定。

### 9.2 程序化调用

```python
import asyncio
from main import run_analysis_with_blackboard

final_state, token_report = asyncio.run(run_analysis_with_blackboard(
    sample_project_name="malware_sample_001",
    # input_name="module.upx",  # 可选：指定 data/input/ 下的导出目录
    resume=False,
))
```

### 9.3 环境要求

- Python 3.10+
- 根目录 `config.yaml`（模型/路径/分析默认值，随仓库提交）
- `.env` 中的 `API_KEY`（唯一必需的机密配置；`BASE_URL` / `MODEL` 等已迁移至 `config.yaml`，环境变量仅作兜底）
- IDA 无 MCP 导出目录（strings.txt, exports.txt, imports.txt, function_index.txt）
