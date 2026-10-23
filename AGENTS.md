# AGENTS.md — multi-agent-adk

> 本文件面向 AI Coding Agent 读者。项目的主要注释和文档使用简体中文，因此本文件以简体中文撰写。
> 
> 更新时间：2026-10-17。以下内容基于仓库当前实际文件，不做假设性推断。

---

## 1. 项目概述

`multi-agent-adk` 是一个基于 **LangGraph 1.x**（`langgraph>=1.0`，`StateGraph`）的 **Windows PE 恶意样本静态分析多 Agent 系统**（项目名沿用自早期的 Google ADK 实现，框架已迁移）。核心设计为：

- **静态分析为主**：不直接运行可疑二进制，输入是分析师从 IDA 导出的文本产物（`strings.txt`、`imports.txt`、`exports.txt`、`function_index.txt`，以及可选的 `decompile/`、`disassembly/`）。
- **分阶段递进**：Phase -1 预提取 → Phase 0 快速定性（3 Worker 并行）→ Phase 1 行为定型 + 函数筛选（2 Worker 并行）→ Phase 2 调度 + 人工审查（HITL）→ Phase 3 函数级深度分析（节点内串行循环）→ Phase 4 综合报告（Map-Reduce）。
- **黑板（Blackboard）上下文管理**：通过 `data/output/{project_name}/` 持久化 `extracts/`（Phase -1 预提取分片）与 `entries/`（版本化条目库，内存态经 `store.pickle` 原子快照落盘、保留最近 10 份备份），实现断点续跑和条目级通信，避免小模型上下文溢出。旧的 artifact + summary 双层文件流已移除。
- **Token 可观测**：完整统计每个阶段/每个节点的 prompt/candidate/total tokens。

项目名：`multi-agent-adk`（`pyproject.toml`）。版本 `0.1.0`，要求 Python `>=3.10`。

---

## 2. 技术栈与关键配置

### 2.1 依赖与包管理

- **构建/包管理**：使用 `pyproject.toml` + `uv.lock`，本地已存在 `.venv/`。建议用 `uv` 或标准 `pip` 安装。
- **核心依赖**：
  - `langgraph>=1.0`（`StateGraph`、START/END、checkpointer、`Send`）
  - `langchain>=1.0`（`langchain.agents.create_agent`、`init_chat_model`、callbacks）
  - `langchain-openai>=1.0`（OpenAI 兼容端点）
  - `pydantic>=2.0`
  - `python-dotenv>=1.0`
- **二进制解析库**：`pefile`、`capstone` **不是**项目依赖。如果需要生成 `pe_info.json`，请单独安装并在分析流程外运行。

### 2.2 全局配置（config.yaml）

运行时配置集中在根目录 **`config.yaml`**（已提交，勿写入机密），由 `config.py` 统一读写。优先级：**config.yaml > 环境变量 > 代码默认值**（无 CLI 参数）。

```yaml
llm:
  model: deepseek-flash                  # env 回退: MODEL
  base_url: https://api.deepseek.com/v1  # env 回退: BASE_URL
  thinking: disabled                     # 思考模式与 Worker 结构化输出的强制 tool_choice 不兼容
  max_context_tokens: 128000             # 所有 agent 单次调用输入上限
  api_key_env: API_KEY                   # .env 中的变量名，决定本次分析用哪个 key
  # api_key: null                        # 可选：直接写字面量 key（优先级高于 api_key_env）
paths:
  input_root: data/input                 # *_export_for_ai 自动发现
  output_root: data/output               # 黑板输出根目录
analysis:
  project_name: module                   # data/output/ 下的存档名
  input_name: null                       # data/input/ 下导出目录名，null 表示自动匹配
  resume: false                          # 断点续跑
agents:
  tool_mode: minimal                     # Agent 工具模式：minimal（默认）/ full
```

读取入口：`config.cfg("llm.model", env="MODEL", default=...)`（另有 `cfg_int` / `cfg_bool`）；写回入口：`config.write_config({...})`（深合并，值为 `None` 表示删键，写盘后自动重置快照）。

**快照语义**：进程首次读取 `config.yaml` 后立即深拷贝一份冻结快照，文件句柄当场释放；此后所有 `cfg()` 只查快照，不再 stat / 重读文件。因此并行运行多个分析进程时，任一进程改写共享的 `config.yaml` 不会影响正在运行的进程（各自持有启动时的配置视图）。需要重新读盘时调用 `config.reset_config_cache()`——这是测试 chdir 到临时目录后重新加载的唯一逃生门（`tests/conftest.py` 的 autouse fixture 每个用例前后都会调它）。

**`API_KEY` 仍放 `.env`**（已 gitignore）。`config.yaml` 的 `llm.api_key_env` 只记录变量名，决定本次分析用哪个 key（可放多个 key 用不同变量名分散并行配额）；`llm.api_key` 字面量优先于该环境变量，但不推荐。`graph.runtime.get_llm()` 用上述配置构造 `init_chat_model(..., extra_body={"thinking": ...})`，**不再需要 `GOOGLE_API_KEY`**。测试用 `graph.runtime.set_llm(fake)` 或 `build_graph(llm=fake)` 注入假模型。

### 2.3 pytest 配置

`pyproject.toml` 中已配置：

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py", "???_test_*.py"]  # 兼容 unit/tools 下 010_ 等阅读顺序前缀
```

---

## 3. 代码组织与主要模块

```
multi-agent-adk/
├── main.py                           # 运行时入口：读 config.yaml 后跑 run_analysis_with_blackboard
├── graph/                            # 编排包
│   ├── __init__.py                   # 导出 build_graph
│   ├── builder.py                    # 唯一编排定义处：build_graph(llm, checkpointer)
│   ├── gates.py                      # 阶段门控节点：pre_extract / resolve_guides / approval_gate
│   ├── workers.py                    # make_worker_node 节点工厂与产物投影
│   ├── phase3.py                     # make_phase3_node：函数级深度分析（节点内串行循环）
│   ├── phase4.py                     # 分片综合 / 聚合节点（Map-Reduce）
│   ├── runtime.py                    # get_llm/set_llm、invoke_guarded、上下文预算、JSON 容错解析
│   ├── state.py                      # AnalysisState(TypedDict)：六个控制字段
│   └── observability.py              # TokenStatsCallback：按 langgraph_node 聚合 token 用量
├── config.py                         # 全局配置读写入口（cfg/cfg_int/cfg_bool/write_config）
├── config.yaml                       # 全局配置（llm/paths/analysis，已提交，勿写机密）
├── pyproject.toml                    # 项目元数据 + pytest 配置
├── uv.lock                           # uv 锁定文件
├── .env                              # API Key（敏感，已 gitignore）
├── tools/                            # FunctionTool 实现
│   ├── file_loaders.py               # IDA 导出文件加载 / Phase -1 预提取（pre_extract_sample）
│   ├── pe_utils.py                   # Shannon 熵计算等 PE 辅助
│   ├── blackboard_tools.py           # 原始证据读取：extracts 分片、函数反编译片段
│   ├── entry_models.py               # 条目/版本/Payload 模型（公共枚举以整数存储，见 5.4）
│   ├── entry_store.py                # ProjectStore：版本化条目库，pickle 原子快照 + 备份恢复
│   ├── entry_tools.py                # 条目读写/查询/上下文构建/review/checkpoint/日志/产物投影
│   ├── agent_tools.py                # get_agent_tools：按角色与模式（minimal/full）装配 Agent 工具集
│   └── token_stats.py                # Token 统计（StageTokenStats / AnalysisTokenReport）
├── workers/                          # Worker 定义
│   ├── specs.py                      # WorkerSpec frozen dataclass + 6 个 spec（5 worker + scheduler）
│   ├── shared_prompts.py             # 五段式提示词模板 + JSON/置信度规则
│   ├── knowledge/                    # 专项分析方法论知识库（arch_detection 路由 + load_arch_guide 工具）
│   ├── phase0/                       # 快速定性（提示词常量）
│   │   ├── string_artifact_analyst.py
│   │   ├── api_behavior_profiler.py
│   │   └── export_interface_analyzer.py
│   ├── phase1/                       # 行为定型 + 函数筛选（提示词常量）
│   │   ├── behavior_profile_synthesizer.py
│   │   └── function_boundary_detector.py
│   ├── phase2/
│   │   └── scheduler.py              # Phase 2 调度器提示词
│   ├── phase3/
│   │   └── function_deep_analyzer.py # 函数级深度分析 prompt 构建
│   └── phase4/
│       └── synthesis_agent.py        # 分片综合 / 聚合 prompt
├── tests/                            # 测试集（编排层通过假模型注入 + graph.ainvoke 离线运行）
│   ├── conftest.py                   # 公共 fixture：每用例前后重置 config 快照、测试后关闭条目库
│   ├── fake_llm.py                   # 共享的脚本化假聊天模型与最小 IDA 导出 fixture
│   ├── unit/                         # 单元测试
│   │   ├── test_config.py
│   │   ├── tools/                    # file_loaders / pe_utils / 条目库 / Agent 工具
│   │   ├── workers/                  # WorkerSpec / 提示词 / 产物投影 / 知识库
│   │   └── graph/                    # 图结构、上下文预算、Token 报告、节点本地行为
│   └── integration/                  # ainvoke 端到端、HITL、预提取目录、故障恢复
├── data/
│   ├── input/module.upx_export_for_ai/  # 示例 fixture（IDA 导出产物，自动发现输入）
│   └── output/                          # 黑板输出根目录（{project_name}/{extracts,entries}）
└── docs/
    ├── RevAgent_LangGraph迁移方案.md  # ADK → LangGraph 迁移方案
    └── architecture/                 # 架构图示（HTML/PNG，历史产物）
```

### 3.1 Worker Agent 设计模式

每个 Worker 的提示词仍使用统一的**五段式提示词**（常量在各 `workers/phaseX/*.py` 原模块，文本未改）：
1. 角色定义
2. 输入数据说明
3. 分析维度
4. 输出格式约束（强制 JSON）
5. 置信度与误差控制

框架层定义在 `workers/specs.py`：每个 Worker 是一个 **`WorkerSpec` frozen dataclass**（`name` / `instruction` / `output_schema`），共 6 个 spec（5 个 worker + scheduler）。Worker 不再直接是 Agent 实例，而是由 `graph.workers.make_worker_node(spec, llm)` 编译为 LangGraph 节点函数：节点内 `create_agent`（ReAct 循环 + `response_format` 结构化输出，失败回退 `parse_json_loose` 容错解析 + `SummarizationMiddleware` 上下文压缩），执行后同一节点内经 `bb_write_worker_output` 将结构化输出投影为版本化条目（样本级发现/候选函数/调度决策等），最终返回 `{}`——分析产物不回流图状态。每个 Worker 的工具集由 `tools/agent_tools.get_agent_tools(role, project, run_id, export_dir, mode)` 按角色和模式动态装配。

### 3.2 黑板数据流（实际已落地）

- **Phase -1**（`pre_extract_node` 调 `pre_extract_sample`）：把 `strings.txt` / `imports.txt` / `exports.txt` / `function_index.txt` 解析为 `data/output/{project}/extracts/*.json`；随后调用 `detect_sample_type` 自动判定样本类型并写入图状态（`sample_type` 永远 auto，不由 CLI 传入）；生成 `run_id` 并经 `bb_set_runtime` 持久化到条目库 runtime；`resume=True` 且存在 checkpoint 时整个节点跳过。
- **条目库**：所有分析产物以**版本化条目**（`tools/entry_store.py` 的 `ProjectStore`）存储于 `entries/store.pickle`：每次写入即追加不可变版本（含 reason/reviewer 元数据），公共枚举以整数存储（见 5.4）。内存态按写入次数/定时器原子快照落盘，保留最近 10 份 `store.bak.NNN.pickle` 备份，损坏时自动从备份恢复。
- **Phase 0 Worker** 读取 `extracts/` 分片 → 输出结构化 `WorkerOutput` → 节点内 `bb_write_worker_output` 投影为样本级发现条目（`enum_to_int` 存储），幂等键为 `(run_id, phase, worker_name, subject_key)`。
- **知识指南门控（Phase 0→1）**：Phase 0 字符串分析输出 `arch_detection`；`graph.gates.resolve_guides_node` 据此匹配知识库并把激活指南写入条目库 runtime。Phase 1 经 `load_arch_guide("__active__")` 按需加载，Phase 3 注入函数分析 prompt。
- **Phase 1 Worker** 经 `bb_build_context` 读取 Phase 0 条目构建上下文 → 输出 `WorkerOutput` → 投影为行为定型条目与函数候选条目。
- **Phase 2 Scheduler** 经 `bb_build_context` 读取条目，生成决策写入 `scheduler_decision` 条目；HITL 由 `graph.gates.approval_gate_node` 负责（CLI `input()`，CONFIRM / MODIFY 协议，3 次无效默认 CONFIRM），人工决定以 `bb_review_entries` 落盘为条目的 review 版本。
- **Phase 3**（`make_phase3_node`，节点内串行循环）：从审批门选定的候选函数出发，逐个调用 `load_function_data` 加载反编译/反汇编片段并 `llm.ainvoke`；幂等键跳过已完成函数；结果以深度分析条目版本追加，每函数完成后 `bb_checkpoint`。
- **Phase 4**：`shard_synthesis`（Map，每 5 个可疑函数一片，串行为小模型稳定性保留）→ `aggregator`（Reduce）经 `bb_build_context`/`bb_query_entries` 读取条目生成最终报告条目，只把条目 id 写回图状态 `final_report_entry_id`。

---

## 4. 构建、运行与测试命令

### 4.1 环境准备

```bash
# 方式 1：uv（推荐，与 uv.lock 一致）
uv venv
uv pip install -e ".[dev]"   # 当前 pyproject 没有 [dev]，直接 uv pip install -e .

# 方式 2：标准 pip
python -m venv .venv
source .venv/bin/activate      # Windows Git Bash: source .venv/Scripts/activate
pip install -e .
```

创建 `.env`（已 gitignore，勿提交）：

```env
API_KEY=your_key_here
```

其余运行时配置（模型、端点、路径、分析默认值）都在根目录 `config.yaml`，见 2.2 节。`.env` 里的变量名要与 `config.yaml` 的 `llm.api_key_env`（默认 `API_KEY`）一致；多个并行进程可用不同变量名（如 `API_KEY_2`）分散配额。

### 4.2 运行方式

**CLI（无参数）**

```bash
source .venv/bin/activate
# 输入放 data/input/ 下的 *_export_for_ai 目录，自动发现
# 项目名、输入目录、是否续跑全部来自 config.yaml 的 analysis.*
python main.py
```

已彻底移除 CLI 参数（原 `-p` / `-i` / `-r`）：配置唯一来源是 `config.yaml` 的 `analysis.*`（环境变量 `PROJECT_NAME` / `INPUT_NAME` / `RESUME` 兜底）。`analysis.project_name` 缺失时 `main()` 抛 `RuntimeError` 并提示配置位置。配置文件在进程启动时读一次即冻结，因此可以同时运行多个进程分析不同样本——运行前改好各自 `analysis.*` 再启动即可，中途对 `config.yaml` 的改动（包括另一个进程的写入）不会影响已在运行的进程。输入目录解析规则：`analysis.input_name` 指定 > project-name 前缀匹配 > 唯一候选自动选用。不再需要 `--export-dir` / `--work-dir` / `--sample-type`：样本类型永远 auto，由 `pre_extract` 节点调 `detect_sample_type` 判定。

**程序化调用（带黑板与断点）**

```python
import asyncio
from main import run_analysis_with_blackboard

final_state, token_report = asyncio.run(run_analysis_with_blackboard(
    sample_project_name="sample_001",
    # input_name="module.upx",  # 可选：指定 data/input/ 下的导出目录
    resume=False,
))
```

### 4.3 测试命令

```bash
source .venv/bin/activate
pytest

# 仅运行不依赖 fixture 数据的测试
pytest -k "not fixture"   # 或手动跳过缺失 data/ 的情况

# 高冗模式查看跳过原因
pytest -v
```

测试全部使用临时目录，不会污染仓库；依赖 `data/input/module.upx_export_for_ai/` 的测试会在 fixture 缺失时自动 `pytest.skip`。

---

## 5. 代码风格与开发约定

- **语言**：源码中注释与 docstring 一律使用中文，技术术语保留英文。新增代码保持这一风格。
- **缩进**：4 空格，不换行符特别要求。
- **类型提示**：使用 `typing`（`Dict`, `List`, `Any`, `Optional`）或 3.10+ 的 `|` 联合类型（当前代码两种都有）。
- **错误处理**：Tool 函数统一返回 `{"status": "success|error", "error": None|str, ...}`，禁止直接抛出异常给上层；纯函数节点（如 `pre_extract_node`）允许抛出 `RuntimeError` 中止整轮分析。
- **JSON 输出**：写入文件时统一使用 `ensure_ascii=False, indent=2`。
- **条目枚举存储**：`tools/entry_models.py` 的公共枚举（`EntryType` / `SubjectKind` / `DataValidationStatus` / `ConclusionValidationStatus` / `ReviewStatus` 等）在条目 payload 中**以整数存储**（经 `enum_to_int`），读取侧再解析回枚举；新增枚举字段必须遵循同一约定。
- **路径**：使用 `pathlib.Path` 或 `os.path.join`，跨平台兼容；黑板路径全部基于当前工作目录下的 `data/output/`（由 `tools.blackboard_tools.board_base_dir()` 决定，读 `config.yaml` 的 `paths.output_root`，环境变量 `BOARD_BASE_DIR` 兜底）。
- **命名**：
  - Worker 模块：`{purpose}_{role}.py`，WorkerSpec `name` 与模块名一致。
  - 图状态（`graph/state.py`）只保留六个控制字段：`sample_project_name` / `sample_export_dir` / `sample_type` / `resume` / `run_id` / `final_report_entry_id`；不再承载 worker payload（旧 `string_analysis` 等 output_key 字段已随条目化移除）。
  - 产物投影键：`bb_write_worker_output` 按 `(run_id, phase, worker_name, subject_key)` 生成幂等键；full 模式 Agent 主动写入与框架兜底投影必须使用同一公式。
  - 黑板持久化：`data/output/{project}/entries/store.pickle`（版本化条目库），`extracts/` 仅存 Phase -1 预提取分片。
- **Token 预算**：
  - 所有 agent 单次 LLM 调用输入上限 128k tokens（`MAX_CONTEXT_TOKENS` 可覆盖）：Worker ReAct 循环由 `SummarizationMiddleware` 在 75% 阈值触发摘要压缩；Phase 3 / Phase 4 的直接调用统一走 `graph.runtime.invoke_guarded`（超限先头尾保留式截断，仍超限抛 `RuntimeError`）；
  - Worker 结构化输出（`WorkerOutput`）随版本化条目整存，无摘要硬约束；
  - Phase 3 函数分析 prompt 要求模型输出 ≤1000 tokens。
- **置信度等级**：`high` / `medium` / `low`。`high` 必须有明确、无歧义的证据；不允许猜测不存在的数据。

---

## 6. 测试策略

- **单元测试**（`tests/unit/`）：
  - `tests/unit/tools/test_tools.py`：验证 `file_loaders`/`pe_utils` 对正常/缺失输入的处理。
  - `tests/unit/tools/test_blackboard_tools.py`：验证 extracts 分片读取（缺失文件、分块裁剪），并含旧黑板 API（`bb_read_summary` 等）不被引用的静态检查。
  - `tests/unit/tools/010_test_entry_models.py` / `020_test_entry_store.py` / `030_test_entry_store_persistence.py` / `040_test_entry_tools.py` / `test_agent_tools.py`：验证条目模型、版本规则、pickle 快照与备份恢复、条目工具协议、minimal/full 工具装配（数字前缀表达条目库测试链的阅读顺序）。
  - `tests/unit/workers/test_workers.py` / `test_phase3.py` / `test_phase4.py` / `test_worker_projection.py`：验证 WorkerSpec 存在、名称、schema、prompt 必要字段与产物投影。
  - `tests/unit/workers/test_knowledge.py`：验证知识库注册表、token 预算、`__active__` 解析、`match_guides` 路由。
  - `tests/unit/graph/`：验证 `build_graph` 图结构与状态白名单、上下文预算截断、Token 报告、知识路由、预提取 run_id、Worker/Phase 4 节点本地行为。
  - `tests/unit/test_config.py`：验证 `config.py` 的读取优先级、默认值与快照语义（首次读取后改文件不影响快照、`reset_config_cache()` 后读到新内容、写盘后中途被改写不影响本进程）。
- **集成测试**（`tests/integration/`）：
  - `test_graph_e2e.py`：验证 `graph.ainvoke` 端到端编排（假模型注入）、TokenStatsCallback 报告统计、运行入口退出落盘。
  - `test_hitl_approval.py`：验证 approval_gate HITL 协议解析与 CONFIRM / MODIFY / 默认放行的审查写入。
  - `test_pre_extract_dirs.py`：验证预提取生成 `data/output/` 目录结构与 extracts 分片。
  - `test_entry_context.py`：验证 `bb_build_context` 的过滤、排序、预算与分页。
  - `test_fault_tolerance.py`：验证条目库落盘后 runtime checkpoint 恢复（`shutdown_stores` 后 `bb_load_checkpoint` 仍可读）。
- **Fixture**：`data/input/module.upx_export_for_ai/` 提供真实的 IDA 导出数据，用于测试 `pre_extract_sample`、`load_function_data` 和目录结构。缺失时自动跳过。
- **Mock**：LLM 调用在测试中全部通过假模型完成（`graph.runtime.set_llm(fake)` 或 `build_graph(llm=fake)`，配合 LangChain `FakeListChatModel` / 自定义 fake chat model），**不会在测试里消耗真实 API token**。

---

## 7. 安全与操作注意事项

- **恶意样本**：项目是分析工具，但当前实现只处理**静态文本导出**，不会执行原始二进制。不要在本项目代码中引入自动执行样本或自动下载 Payload 的逻辑。
- **API Key**：`.env` 已加入 `.gitignore`，Agent 不应读取或修改 `.env`；若需要新增环境变量，应提醒用户在本地 `.env` 中自行配置。
- **HITL（人在回路）**：Phase 2 结束后 `approval_gate` 节点会在 CLI 阻塞等待人工输入，必须回复 `CONFIRM` 或 `MODIFY <addr1>,<addr2>,...` 才会继续 Phase 3（3 次无效输入默认 CONFIRM 放行）。不要绕过该节点自动继续。
- **数据残留**：运行时会生成 `data/output/`、`.pytest_cache/`。`data/` 与 `.pytest_cache/` 均已 gitignore，部署或打包时无需包含。
- **URL/IOC 处理**：Worker 可能从样本中提取 C2 URL、文件路径等敏感 IoC。黑板中的条目库（`entries/store.pickle`）与 extracts 应被视为敏感分析数据，按组织安全策略保管。

---

## 8. 当前已知问题与开发陷阱

> 以下内容基于当前代码实际状态，Agent 在修改前应特别注意。

1. ~~编排层历史债务~~ —— **已通过 LangGraph 迁移根治**（2026-09-22）：Phase 0→4 全部统一在 `graph/builder.py` 组装的单一 `StateGraph` 中，阶段门控 checkpoint 与 HITL 审批门都是普通节点，不再有手写 Runner 循环。

2. ~~HITL 与框架回调耦合~~ —— **已通过 LangGraph 迁移根治**（2026-09-22）：HITL 是 `approval_gate` 普通节点，`graph/builder.py` 完全控制 Phase 2→3 流转；`interrupt()` 化 + SqliteSaver 恢复是 Step 2 待办。

3. ~~Worker 提示词幻觉风险~~ —— **已缓解**（2026-06-09）：全部 Worker 增加数据充足性检查、证据链约束、最简 schema（2层嵌套上限）、具体反幻觉规则。

4. **测试的 cwd 敏感性**
   - 黑板测试和预提取测试会 `os.chdir(tempdir)`。Windows 下临时目录句柄可能未释放，测试里已经设置 `ignore_cleanup_errors=True`；本地运行若遇到权限错误，通常是杀毒软件或文件句柄未释放，重试即可。

---

## 9. 常用扩展点

| 需求 | 推荐修改位置 |
|------|-------------|
| 调整全局配置（模型/路径/分析默认值） | 直接编辑根目录 `config.yaml`；新增配置项在 `config.py` 用 `cfg()` 读取 |
| 新增一个 Phase 0/1 Worker | `workers/phaseX/` 新增提示词模块，在 `workers/specs.py` 声明 WorkerSpec，在 `graph/builder.py` 加节点与边；产物投影规则在 `tools/entry_tools.py` |
| 调整 Worker 提示词 | 直接修改对应 `workers/phaseX/xxx.py` 中的 `INSTRUCTION` 常量（无需动 specs.py） |
| 调整 Agent 工具集（minimal/full） | `tools/agent_tools.py` 的 `MINIMAL_ROLE_TOOLS` 映射与 `make_minimal_tools` |
| 修改黑板目录结构 | `tools/blackboard_tools.py` 中的 `board_base_dir` 和 `_ensure_dirs`；条目库存储策略在 `tools/entry_store.py` |
| 新增样本类型（LNK/ELF） | 新增 `workers/optional/` 提示词 + spec，在 `detect_sample_type` 和 `graph/builder.py` 中动态加载 |
| 修改 Token 统计字段 | `tools/token_stats.py` 中的 `StageTokenStats` / `AnalysisTokenReport`；节点归属逻辑在 `graph/observability.py` |
| 调整图结构 / 编排 | `graph/builder.py`（加边/加节点）、`graph/gates.py`（门控节点）与 `graph/workers.py`（节点工厂与产物投影） |

> 注：`docs/superpowers/` 下的设计与计划文档为本地工作文件，已被 `.gitignore` 忽略，不要提交。

---

## 10. 参考资料

- `ARCHITECTURE.md`：项目架构指南（中文），包含 LangGraph 图示、Worker 职责、AnalysisState 字段规范、扩展路线图。
- `docs/RevAgent_LangGraph迁移方案.md`：ADK → LangGraph 迁移方案，记录了新架构的设计决策。
- `docs/architecture/`：历史架构图示（HTML/PNG），仅供参考，可能与当前实现有出入。
