# AGENTS.md — multi-agent-adk

> 本文件面向 AI Coding Agent 读者。项目的主要注释和文档使用简体中文，因此本文件以简体中文撰写。
> 
> 更新时间：2026-06-08。以下内容基于仓库当前实际文件，不做假设性推断。

---

## 1. 项目概述

`multi-agent-adk` 是一个基于 Google ADK（`google-adk>=0.2.0`）的 **Windows PE 恶意样本静态分析多 Agent 系统**。核心设计为：

- **静态分析为主**：不直接运行可疑二进制，输入是分析师从 IDA 导出的文本产物（`strings.txt`、`imports.txt`、`exports.txt`、`function_index.txt`，以及可选的 `decompile/`、`disassembly/`）。
- **分阶段递进**：Phase -1 预提取 → Phase 0 快速定性（3 Worker 并行）→ Phase 1 行为定型 + 函数筛选（2 Worker 并行）→ Phase 2 调度 + 人工审查（HITL）→ Phase 3 函数级深度分析（动态循环）→ Phase 4 综合报告。
- **黑板（Blackboard）上下文管理**：通过 `.blackboard/{project_name}/` 持久化 `extracts/`、`artifacts/`、`summary/`、`meta/`，实现断点续跑和摘要级通信，避免小模型上下文溢出。
- **Token 可观测**：完整统计每个阶段/每个 Worker 的 prompt/candidate/total tokens。

项目名：`multi-agent-adk`（`pyproject.toml`）。版本 `0.1.0`，要求 Python `>=3.10`。

---

## 2. 技术栈与关键配置

### 2.1 依赖与包管理

- **构建/包管理**：使用 `pyproject.toml` + `uv.lock`，本地已存在 `.venv/`。建议用 `uv` 或标准 `pip` 安装。
- **核心依赖**：
  - `google-adk>=0.2.0`（Workflow、`LlmAgent`、FunctionNode、Runner、InMemorySessionService）
  - `pydantic>=2.0`
  - `python-dotenv>=1.0`
- **二进制解析库**：`pefile`、`capstone` **不是** ADK 依赖。如果需要生成 `pe_info.json`，请单独安装并在 ADK 流程外运行。

### 2.2 模型配置

运行时通过 `.env` 读取（文件被 gitignore，不要在仓库中提交）：

- `MOONSHOT_API_KEY`（必填）
- `MOONSHOT_BASE_URL`（默认 `https://api.moonshot.cn/v1`）
- `MOONSHOT_MODEL`（默认 `openai/kimi-k2.5`，代码里会自动补 `openai/` 前缀以适配 `LiteLlm`）

`agent.py` 使用 `google.adk.models.lite_llm.LiteLlm` 包装为 OpenAI 兼容调用。ADK 某些内部行为可能仍需要 `GOOGLE_API_KEY`，若报错请补充。

### 2.3 pytest 配置

`pyproject.toml` 中已配置：

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
```

---

## 3. 代码组织与主要模块

```
multi_agent_adk/
├── agent.py                          # 根代理、Token 统计、运行时入口（run_analysis / run_analysis_with_blackboard）
├── pyproject.toml                    # 项目元数据 + pytest 配置
├── uv.lock                           # uv 锁定文件
├── .env                              # API Key（敏感，已 gitignore）
├── __init__.py                       # ADK CLI 入口：导出 root_agent
├── tools/                            # FunctionTool 实现
│   ├── file_loaders.py               # IDA 导出文件加载 / Phase -1 预提取（pre_extract_sample）
│   ├── pe_utils.py                   # Shannon 熵计算等 PE 辅助
│   └── blackboard_tools.py           # 黑板读写、checkpoint、日志、函数反编译片段加载
├── workers/                          # Worker Agent 定义
│   ├── shared_prompts.py             # 五段式提示词模板 + JSON/置信度规则
│   ├── extractor.py                  # 摘要提取器 Agent（将 artifact 压缩为 ≤1500 tokens 的 summary）
│   ├── phase0/                       # 快速定性
│   │   ├── string_artifact_analyst.py
│   │   ├── api_behavior_profiler.py
│   │   └── export_interface_analyzer.py
│   ├── phase1/                       # 行为定型 + 函数筛选
│   │   ├── behavior_profile_synthesizer.py
│   │   └── function_boundary_detector.py
│   ├── phase3/
│   │   └── function_deep_analyzer.py
│   └── phase4/
│       └── synthesis_agent.py
├── callbacks/
│   └── human_review.py               # Phase 2 完成后触发的人工审查回调
├── tests/                            # 测试集
│   ├── test_tools.py                 # file_loaders / pe_utils 单元测试
│   ├── test_workers.py               # Worker 存在性与 output_key 测试
│   ├── test_integration.py           # orchestrator / token 报告 / setup_fn 测试
│   ├── test_blackboard_tools.py      # 黑板读写/checkpoint/日志测试
│   ├── test_extractor.py             # 摘要提取器测试
│   ├── test_fault_tolerance.py       # 容错与摘要大小限制测试
│   ├── test_pre_extract.py           # Phase -1 预提取测试
│   ├── test_phase3.py                # 函数数据加载与函数级分析器测试
│   └── test_phase4.py                # 综合报告 Agent 测试
├── data/module.upx_export_for_ai/    # 示例 fixture（IDA 导出产物）
└── docs/superpowers/                 # 设计文档与历史计划（specs + plans）
```

### 3.1 Worker Agent 设计模式

每个 Worker 使用统一的**五段式提示词**：
1. 角色定义
2. 输入数据说明
3. 分析维度
4. 输出格式约束（强制 JSON）
5. 置信度与误差控制

所有 Worker 都是 `LlmAgent`，带有 `name`、`instruction`、`tools`、`output_key`。

### 3.2 黑板数据流（实际已落地）

- **Phase -1**（`pre_extract_sample`）：把 `strings.txt` / `imports.txt` / `exports.txt` / `function_index.txt` 解析为 `.blackboard/{project}/extracts/*.json`。
- **Phase 0 Worker** 读取 `extracts/` 分片 → 输出完整 artifact 到 `artifacts/p0_*_{timestamp}.json`。
- **Extractor Agent** 将 artifact 提炼为 `summary/{strings,api,exports}_summary.json`（硬约束 ≤1500 tokens）。
- **Phase 1 Worker** 读取 `summary/` + `extracts/` → 输出 `artifacts/p1_*_{timestamp}.json` → 再提炼为 `summary/`。
- **Phase 2 Scheduler** 读取 summary，生成决策并触发 `human_review_callback`。
- **Phase 3** 从 `summary/p2_decision.json` 读取待分析函数队列，逐个调用 `load_function_data` 加载反编译/反汇编片段，动态创建 Analyzer Agent，结果存入 `artifacts/phase3_func_{addr}.json` 和 `summary/phase3_funcs/`。
- **Phase 4** 读取所有 summary，生成 `summary/p4_final_report.json`。

---

## 4. 构建、运行与测试命令

### 4.1 环境准备

```bash
# 方式 1：uv（推荐，与 uv.lock 一致）
uv venv
uv pip install -e ".[dev]"   # 当前 pyproject 没有 [dev]，直接 uv pip install -e .

# 方式 2：标准 pip
python -m venv .venv
source .venv/Scripts/activate    # Windows Git Bash
pip install -e .
```

创建 `.env`（已 gitignore，勿提交）：

```env
MOONSHOT_API_KEY=your_key_here
MOONSHOT_BASE_URL=https://api.moonshot.cn/v1
MOONSHOT_MODEL=kimi-k2.5
```

### 4.2 运行方式

**ADK CLI（目前仅 setup_fn HITL 路径可用）**

```bash
source .venv/Scripts/activate
adk run .
```

CLI 会触发 `setup_fn` 的 `RequestInput`，要求输入：

```text
EXPORT_DIR=<IDA 导出目录完整路径>
PROJECT_NAME=<项目名>
WORK_DIR=<可选工作目录>
```

也支持单行管道格式：

```text
EXPORT_DIR=D:\analysis\sample_001_export|PROJECT_NAME=sample_001|WORK_DIR=D:\analysis\output
```

**程序化调用（带黑板与断点）**

```python
import asyncio
from agent import run_analysis_with_blackboard

asyncio.run(run_analysis_with_blackboard(
    sample_export_dir="/path/to/ida/export",
    sample_project_name="sample_001",
    sample_type="pe",
    resume=False,
))
```

### 4.3 测试命令

```bash
source .venv/Scripts/activate
pytest

# 仅运行不依赖 fixture 数据的测试
pytest -k "not fixture"   # 或手动跳过缺失 data/ 的情况

# 高冗模式查看跳过原因
pytest -v
```

测试全部使用临时目录，不会污染仓库；依赖 `data/module.upx_export_for_ai/` 的测试会在 fixture 缺失时自动 `pytest.skip`。

---

## 5. 代码风格与开发约定

- **语言**：源码中注释以中文为主，docstring 以英文为主。新增代码保持这一风格。
- **缩进**：4 空格，不换行符特别要求。
- **类型提示**：使用 `typing`（`Dict`, `List`, `Any`, `Optional`）或 3.10+ 的 `|` 联合类型（当前代码两种都有）。
- **错误处理**：Tool 函数统一返回 `{"status": "success|error", "error": None|str, ...}`，禁止直接抛出异常给上层。
- **JSON 输出**：写入文件时统一使用 `ensure_ascii=False, indent=2`。
- **路径**：使用 `pathlib.Path` 或 `os.path.join`，跨平台兼容；黑板路径全部基于当前工作目录下的 `.blackboard/`。
- **命名**：
  - Worker 模块：`{purpose}_{role}.py`，Agent 实例名与模块名一致。
  - `output_key` 规范：`string_analysis`、`api_behavior_analysis`、`export_interface_analysis`、`behavior_profile`、`function_boundary_analysis`、`scheduler_decision`、`final_report`。
  - 黑板 summary 名：`strings_summary`、`api_summary`、`exports_summary`、`behavior_summary`、`functions_summary`、`p2_decision`、`p4_final_report`。
- **Token 预算**：
  - Worker 输出 artifact 无明确上限；
  - Extractor 产出 summary 必须 ≤1500 tokens（`blackboard_tools.bb_write_summary` 会硬拦截）；
  - Phase 3 函数分析 prompt 要求模型输出 ≤1000 tokens。
- **置信度等级**：`high` / `medium` / `low`。`high` 必须有明确、无歧义的证据；不允许猜测不存在的数据。

---

## 6. 测试策略

- **单元测试**：
  - `test_tools.py`：验证 `file_loaders`/`pe_utils` 对正常/缺失输入的处理。
  - `test_blackboard_tools.py`：验证 summary 大小限制、checkpoint、artifact 存在性、日志追加。
  - `test_workers.py` / `test_extractor.py` / `test_phase3.py` / `test_phase4.py`：验证 Agent 存在、名称、output_key、prompt 包含必要字段。
- **集成测试**：
  - `test_integration.py`：验证 orchestrator、token 报告统计、setup_fn HITL、`_parse_config_from_text` 多格式解析、预提取生成 `.blackboard/` 目录结构。
  - `test_fault_tolerance.py`：验证失败后的状态恢复和摘要大小拒绝。
- **Fixture**：`data/module.upx_export_for_ai/` 提供真实的 IDA 导出数据，用于测试 `pre_extract_sample`、`load_function_data` 和目录结构。缺失时自动跳过。
- **Mock**：LLM 调用在测试中全部通过 Mock event / Mock usage metadata 完成，**不会在测试里消耗真实 API token**。

---

## 7. 安全与操作注意事项

- **恶意样本**：项目是分析工具，但当前实现只处理**静态文本导出**，不会执行原始二进制。不要在本项目代码中引入自动执行样本或自动下载 Payload 的逻辑。
- **API Key**：`.env` 已加入 `.gitignore`，Agent 不应读取或修改 `.env`；若需要新增环境变量，应提醒用户在本地 `.env` 中自行配置。
- **HITL（人在回路）**：Phase 2 结束后会进入 `WAITING_FOR_APPROVAL` 状态，必须由人工审查后回复 `CONFIRM` 或 `MODIFY ...`。不要绕过该回调自动继续。
- **数据残留**：运行时会生成 `.blackboard/`、`.adk/session.db`、`.pytest_cache/`。这些目录均已 gitignore，部署或打包时无需包含。
- **URL/IOC 处理**：Worker 可能从样本中提取 C2 URL、文件路径等敏感 IoC。黑板中的 artifact/summary 应被视为敏感分析数据，按组织安全策略保管。

---

## 8. 当前已知问题与开发陷阱

> 以下内容基于当前代码实际状态，Agent 在修改前应特别注意。

1. **`analysis_orchestrator` 与 `scheduler_agent` 的定义顺序**
   - `analysis_orchestrator` 函数体中引用了 `scheduler_agent`，但 `scheduler_agent` 在 `analysis_orchestrator` 之后定义。Python 函数在调用时才会解析闭包变量，所以导入阶段不会报错；但在运行到 `ctx.run_node(scheduler_agent)` 时必须确保 `scheduler_agent` 已经绑定。

2. **测试的 cwd 敏感性**
   - 黑板测试和预提取测试会 `os.chdir(tempdir)`。Windows 下临时目录句柄可能未释放，测试里已经设置 `ignore_cleanup_errors=True`；本地运行若遇到权限错误，通常是杀毒软件或文件句柄未释放，重试即可。

---

## 9. 常用扩展点

| 需求 | 推荐修改位置 |
|------|-------------|
| 新增一个 Phase 0 Worker | `workers/phase0/` 新增模块，在 `agent.py` 导入并加入 Workflow edges |
| 调整 Worker 提示词 | 直接修改对应 `workers/phaseX/xxx.py` 中的 `INSTRUCTION` |
| 新增文件加载 Tool | `tools/file_loaders.py`，注册到 `agent.py` 的 `ALL_TOOLS` |
| 修改黑板目录结构 | `tools/blackboard_tools.py` 中的 `_board_path` 和 `_ensure_dirs` |
| 新增样本类型（LNK/ELF） | 新增 `workers/optional/` 子 Agent，在 `detect_sample_type` 和 orchestrator 中动态加载 |
| 修改 Token 统计字段 | `agent.py` 中的 `StageTokenStats` / `AnalysisTokenReport` |
| 补全缺失的 Workflow | `agent.py`，参考 `docs/superpowers/specs/2026-06-08-dynamic-workflow-setup-hitl-design.md` |

---

## 10. 参考资料

- `ARCHITECTURE.md`：项目架构指南（中文），包含 Workflow 图示、Worker 职责、状态键规范、扩展路线图。
- `docs/superpowers/specs/`：详细设计文档（黑板上下文管理、动态 Workflow + HITL、MVP 设计）。
- `docs/superpowers/plans/`：历史实施计划，记录了代码演进的决策过程，修改前可参考以理解当前实现动机。
