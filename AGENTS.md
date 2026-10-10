# AGENTS.md — multi-agent-adk

> 本文件面向 AI Coding Agent 读者。项目的主要注释和文档使用简体中文，因此本文件以简体中文撰写。
> 
> 更新时间：2026-10-10。以下内容基于仓库当前实际文件，不做假设性推断。

---

## 1. 项目概述

`multi-agent-adk` 是一个基于 **LangGraph 1.x**（`langgraph>=1.0`，`StateGraph`）的 **Windows PE 恶意样本静态分析多 Agent 系统**（项目名沿用自早期的 Google ADK 实现，框架已迁移）。核心设计为：

- **静态分析为主**：不直接运行可疑二进制，输入是分析师从 IDA 导出的文本产物（`strings.txt`、`imports.txt`、`exports.txt`、`function_index.txt`，以及可选的 `decompile/`、`disassembly/`）。
- **分阶段递进**：Phase -1 预提取 → Phase 0 快速定性（3 Worker 并行）→ Phase 1 行为定型 + 函数筛选（2 Worker 并行）→ Phase 2 调度 + 人工审查（HITL）→ Phase 3 双轨制深度分析（主题轨 + 函数轨，`Send` 分波并行扇出）→ orchestrator 质量编排（纯代码：docs 归档 + 质量/缺口/矛盾检查）→ 验证 Worker（high 置信度发现证据回查）→ Phase 4 综合报告（Map-Reduce）→ 综合参考手册（Markdown 落盘）。
- **黑板（Blackboard）上下文管理**：通过 `data/output/{project_name}/` 持久化 `extracts/`、`artifacts/`、`summary/`、`meta/`，实现断点续跑和摘要级通信，避免小模型上下文溢出。
- **docs 归档层与异步人机沟通**：`data/output/docs/{project_name}/` 归档五要素结论（`AGENT_XX_{主题}.md`）并维护 `USER.md` 异步沟通文档（Agent 写入疑惑/矛盾不阻塞执行流，用户回答在下一波主题分析前注入 prompt）。
- **Token 可观测**：完整统计每个阶段/每个节点的 prompt/candidate/total tokens。

项目名：`multi-agent-adk`（`pyproject.toml`）。版本 `0.1.0`，要求 Python `>=3.10`。

---

## 2. 技术栈与关键配置

### 2.1 依赖与包管理

- **构建/包管理**：使用 `pyproject.toml` + `uv.lock`，本地已存在 `.venv/`。建议用 `uv` 或标准 `pip` 安装。
- **核心依赖**：
  - `langgraph>=1.0`（`StateGraph`、START/END、checkpointer、`Send`）
  - `langgraph-checkpoint-sqlite>=3.0`（`AsyncSqliteSaver`，图状态持久化与 HITL `interrupt()` 恢复）
  - `langchain>=1.0`（`langchain.agents.create_agent`、`init_chat_model`、callbacks）
  - `langchain-openai>=1.0`（OpenAI 兼容端点）
  - `pydantic>=2.0`
  - `python-dotenv>=1.0`
  - `fastapi>=0.115` + `uvicorn>=0.30`（Web UI 审查面板；测试另需 dev extra 的 `httpx`，供 FastAPI TestClient 使用）
- **二进制解析库**：`pefile`、`capstone` **不是**项目依赖。如果需要生成 `pe_info.json`，请单独安装并在分析流程外运行。

### 2.2 全局配置（config.yaml）

运行时配置集中在根目录 **`config.yaml`**（已提交，勿写入机密），由 `config.py` 统一读写。优先级：**CLI 参数 > config.yaml > 环境变量 > 代码默认值**。

```yaml
llm:
  model: deepseek-flash                  # env 回退: MODEL
  base_url: https://api.deepseek.com/v1  # env 回退: BASE_URL
  thinking: disabled                     # 思考模式与 Worker 结构化输出的强制 tool_choice 不兼容
  max_context_tokens: 128000             # 所有 agent 单次调用输入上限
  # 模型分层（B1）：轻任务可用小模型降本；缺省（null）= 与主模型相同，零行为变化
  light_model: null                      # 轻任务模型名（缺省用 llm.model），env 回退: LIGHT_MODEL
  light_base_url: null                   # 轻任务端点（缺省用 llm.base_url），env 回退: LIGHT_BASE_URL
  light_api_key: null                    # 轻任务 key（缺省用 API_KEY；机密建议用 env LIGHT_API_KEY）
paths:
  input_root: data/input                 # *_export_for_ai 自动发现
  output_root: data/output               # 黑板输出根目录
analysis:
  project_name: module                   # CLI -p 覆盖
  input_name: null                       # CLI -i 覆盖
  resume: false                          # CLI -r 覆盖
  phase3_max_concurrency: 4              # Phase 3 并行函数分析的 LLM 并发上限
  phase3_top_n: 20                       # Phase 3 候选函数数量上限
  lib_xref_threshold: 50                 # 候选护栏：xrefs 超过该值的疑似库函数排除
  lib_tail_ratio: 0.45                   # 候选护栏：函数地址范围尾部该比例起算高地址区间
  lib_size_max: 512                      # 候选护栏：size 上限（0=不启用 size 条件）
  token_budget: null                     # 单次分析总 token 预算（null=不启用），env 回退: TOKEN_BUDGET
  focus: null                            # C2 用户重点关注领域（逗号分隔），CLI --focus 覆盖，env 回退: FOCUS
  exclude: null                          # C2 用户排除领域（不深入静态过程），CLI --exclude 覆盖，env 回退: EXCLUDE
```

读取入口：`config.cfg("llm.model", env="MODEL", default=...)`（另有 `cfg_int` / `cfg_bool`）；写回入口：`config.write_config({...})`（深合并，值为 `None` 表示删键）。`config.yaml` 相对当前工作目录解析并按 mtime 缓存，测试 chdir 到临时目录后自动回退到环境变量/默认值。

**`API_KEY` 仍放 `.env`**（已 gitignore，也可在 `llm.api_key` 配置但不推荐）。`graph_nodes.get_llm(tier="strong")` 用上述配置构造 `init_chat_model(..., extra_body={"thinking": ...})`，**不再需要 `GOOGLE_API_KEY`**。

**模型分层（B1，2026-10-10 落地）**：`get_llm(tier)` 双单例缓存——`tier="light"` 且配置了 `llm.light_model` 时返回独立的轻任务模型实例（`light_base_url`/`light_api_key` 缺省分别回退主 `base_url`/`API_KEY`），未配置时直接返回 strong 实例（零行为变化）。分层默认：**light** = 3 个 Phase 0 triage Worker、scheduler、verification_agent、extractor 摘要调用；**strong** = 2 个 Phase 1 Worker、Phase 3 主题/函数节点、shard/aggregator/report_generator。Worker 侧由 `WorkerSpec.tier` 声明（`make_worker_node` 按它取模型）；主题/函数/Phase 4 节点工厂签名为 `make_xxx_node(llm=None, tier="strong")`，`llm` 显式传入时优先。测试用 `graph_nodes.set_llm(fake)`（两个 tier 单例一并替换）或 `build_graph(llm=fake)` 注入假模型——显式注入时所有 tier 都用它，`get_llm` 不会被调用。

**Token 预算闸门（B1，2026-10-10 落地）**：`analysis.token_budget`（env `TOKEN_BUDGET`，null=不启用）限制单次分析总 token。`observability.register_callback(project, callback)` 维护模块级注册表（`main.py` 与 webui 推进任务创建 `TokenStatsCallback` 时注册），`current_total_tokens(project)` 供闸门查实时用量。所有直接 LLM 调用的统一入口 `graph_nodes.invoke_guarded(..., project_name=...)` 调用前先过 `_enforce_token_budget`；Worker ReAct 内层不经 invoke_guarded，故 `make_worker_node` 在主调用入口加同样检查。超预算时 `interrupt({"kind": "token_budget", ...})` 挂起等人工；resume（任意文本）后预算阈值自增一个步长（=基础预算），再次超再挂起，可反复放行。CLI 中断循环本就透传任意 resume 文本无需改动；webui decision 端点对 CONFIRM/MODIFY 之外的字符串原样透传，前端对 `kind=="token_budget"` 显示"继续"按钮。

**focus/exclude 用户分析优先级（C2，2026-10-10 落地）**：`analysis.focus` / `analysis.exclude`（env `FOCUS` / `EXCLUDE`，null=不启用）声明用户重点关注/不深入的分析领域（逗号分隔原文）。链路：CLI `--focus`/`--exclude` 或 Web UI start 请求体 → `initial_state` 的 `user_focus`/`user_exclude` → `pre_extract` 节点经 `graph_nodes._sync_user_priority_to_user_md` 幂等落盘 USER.md"用户着重关心的内容"段（`docs_tools.user_md_set_focus`，resume 时不覆盖用户中途编辑）→ 所有 Worker（`make_worker_node` task 消息）、主题/函数节点（`build_topic_prompt` / `build_func_analysis_prompt` 的 `special_requirements`）、报告节点统一经 `_load_user_special_requirements(project, focus, exclude)` 注入"用户分析重点"段（`build_user_priority_text` 渲染约束文案；启动参数与 USER.md 两来源合一，按原文子串去重）。行为约束对齐金标准：focus 领域优先详写；exclude 领域不展开静态过程、不阻塞整体流程、产物标注"用户指示不深入分析此部分"，结果性数据只给动调提取方案。注意 Send 扇出的是部分状态，`_task_base_payload` 必须显式透传 `user_focus`/`user_exclude`。

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
multi-agent-adk/
├── main.py                           # 运行时入口：CLI 参数解析 + run_analysis_with_blackboard
├── graph.py                          # 唯一编排定义处：build_graph(llm, checkpointer)
├── graph_nodes.py                    # 节点工厂与业务节点（worker/预提取/知识路由/审批门/phase3/phase4）
├── candidate_guards.py               # Phase 3 候选函数代码级护栏（导出置顶 + 库函数排除 + Top N 补足）
├── state.py                          # AnalysisState(TypedDict) + Pydantic 输出模型
├── observability.py                  # TokenStatsCallback：按 langgraph_node 聚合 token 用量
├── config.py                         # 全局配置读写入口（cfg/cfg_int/cfg_bool/write_config）
├── config.yaml                       # 全局配置（llm/paths/analysis，已提交，勿写机密）
├── pyproject.toml                    # 项目元数据 + pytest 配置
├── uv.lock                           # uv 锁定文件
├── .env                              # API Key（敏感，已 gitignore）
├── tools/                            # FunctionTool 实现
│   ├── file_loaders.py               # IDA 导出文件加载 / Phase -1 预提取（pre_extract_sample）
│   ├── pe_utils.py                   # Shannon 熵计算等 PE 辅助
│   ├── blackboard_tools.py           # 黑板读写、checkpoint、日志、函数反编译片段加载
│   ├── docs_tools.py                 # docs 归档层（AGENT_XX 五要素 Markdown）+ USER.md 异步沟通读写
│   └── token_stats.py                # Token 统计（StageTokenStats / AnalysisTokenReport）
├── workers/                          # Worker 定义
│   ├── specs.py                      # WorkerSpec frozen dataclass + 7 个 spec（5 worker + scheduler + verification）
│   ├── shared_prompts.py             # 五段式提示词模板 + JSON/置信度规则
│   ├── extractor.py                  # 摘要提取 prompt 构建（节点内单次 llm.ainvoke 调用）
│   ├── knowledge/                    # 专项分析方法论知识库（arch_detection 路由 + load_arch_guide 工具；
│   │                                 #   C1 扩容后 9 份：windows_pe 基线 / file_loader_triage /
│   │                                 #   cpp / golang / rust / vm_protected / lua_scripted_agent /
│   │                                 #   encrypted_database / yara_embedded，均为提炼改写，每份 ≤1200 tokens）
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
│   │   ├── function_deep_analyzer.py # 函数级深度分析 prompt 构建
│   │   └── verification_agent.py     # 验证 Worker 提示词（high 置信度发现证据回查）
│   ├── topics/
│   │   └── topic_prompts.py          # 主题轨 prompt 构建（五段式 + 8 主题方法论要点，批次 A2）
│   └── phase4/
│       ├── synthesis_agent.py        # 分片综合 / 聚合 prompt
│       └── report_generator.py       # 综合报告 Worker prompt（Markdown 综合参考手册）
├── tests/                            # 测试集（编排层通过假模型注入 + graph.ainvoke 离线运行）
├── webui/                            # Web UI 审查面板（路线图 P3 项，2026-10-09 落地）
│   ├── server.py                     # FastAPI 后端：start/status/review/decision/report + 静态托管
│   └── static/index.html             # 单页面前端（无构建链，marked.js CDN 渲染报告，回退纯文本）
├── data/
│   ├── input/module.upx_export_for_ai/  # 示例 fixture（IDA 导出产物，自动发现输入）
│   └── output/                          # 黑板输出根目录（{project_name}/{extracts,artifacts,summary,meta}
│                                        #   + docs/{project_name}/{AGENT_XX_*.md,USER.md}）
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

框架层定义在 `workers/specs.py`：每个 Worker 是一个 **`WorkerSpec` frozen dataclass**（`name` / `instruction` / `tools` / `output_key` / `output_schema` / `tier`），共 7 个 spec（5 个 worker + scheduler + verification_agent）。Worker 不再直接是 Agent 实例，而是由 `graph_nodes.make_worker_node(spec, llm)` 编译为 LangGraph 节点函数：节点内 `create_agent`（ReAct 循环 + `response_format` 结构化输出，失败回退 `parse_json_loose` 容错解析 + `SummarizationMiddleware` 上下文压缩），执行后同一节点内完成 `bb_write_artifact` + extractor 摘要持久化，最终返回 `{output_key: payload}` 写入图状态。每个 worker 声明最小工具集（2–4 个），不再有 ALL_TOOLS 全量注入。`tier` 字段（B1）声明模型分层：`"light"`（Phase 0 triage 3 个 + scheduler + verification_agent）走轻任务模型，`"strong"`（默认，Phase 1 2 个）走主模型；extractor 摘要一律走 light。

### 3.2 黑板数据流（实际已落地）

- **Phase -1**（`pre_extract_node` 调 `pre_extract_sample`）：把 `strings.txt` / `imports.txt` / `exports.txt` / `function_index.txt` 解析为 `data/output/{project}/extracts/*.json`；随后调用 `detect_sample_type` 自动判定样本类型并写入图状态（`sample_type` 永远 auto，不由 CLI 传入）；`resume=True` 且存在 checkpoint 时整个节点跳过。
  - **B2 规则化预提取加码（零 token，2026-10-10 落地）**：在原有 4 个 extract 之外新增 3 个确定性产物（纯 Python 正则/统计）——`strings_categorized.json`（字符串 8 类单归属分类：pdb_paths / urls / ips / registry_paths / command_lines / mutex_candidates / file_paths / domains，统计 + 明细）、`imports_categorized.json`（API 按功能类单归属：injection / anti_debug / crypto / network / registry / file / process / other，兼容 DLL 分节与 `addr:name` 两种 imports.txt 格式）、`functions_buckets.json`（函数索引四桶分桶，与 `candidate_guards` 同款规则同阈值：exports 导出 > named 有名 > library_suspect 高 xref 无名尾部 > other，随盘记录分桶规则与 tail_start 可审计）。Worker 工具侧 `load_strings` / `load_imports` / `load_function_index` 新增可选 `project_name` 参数：提供且对应分类产物存在时优先返回产物内容（返回结构带 `source` 字段标注来源，产物路径下 `all_strings` 置空避免全量塞上下文），产物不存在时回退原始解析（旧数据兼容，行为不变）。
  - **反编译失败 fallback 路由（B2）**：`function_index.txt` 解析新增 `Type` 字段（`decompile` / `disassembly-fallback`），分桶明细带 `decompile_failed` 标记；`load_function_data` 返回结构新增 `decompile_failed`（伪代码缺失即 True，数据行为不变仅显式标注；反编译/反汇编文件名查找改为大小写不敏感，兼容大写 hex 文件名）。`build_func_analysis_prompt` 检测到 `decompile_failed` 时追加 `DISASM_FALLBACK_SECTION` 反汇编专项段；`build_topic_prompt` 对 fallback 函数块标题标记"（反编译失败，只有反汇编）"并注入一次专项要求（要点：API 调用序列 / 常量魔数 / 缓冲区写入地址 / 循环语义 / 动调断点建议，源自 `workers/knowledge/windows_pe.md` 与 `file_loader_triage.md` 既有方法论；正常函数路径不变）。
- **Phase 0 Worker** 读取 `extracts/` 分片 → 输出完整 artifact 到 `artifacts/p0_*_{timestamp}.json` → extractor 提炼 `summary/{strings,api,exports}_summary.json`（硬约束 ≤1500 tokens）。
- **知识指南门控（Phase 0→1）**：Phase 0 字符串分析输出 `arch_detection`；`graph_nodes.resolve_guides_node` 据此匹配知识库并写入 `meta/active_guides.json`。Phase 1 经 `load_arch_guide("__active__")` 按需加载，Phase 3 注入函数分析 prompt。**C1 扩容（2026-10-10）**：`arch_detection` 新增 `code_frameworks` 多值字段（词表 `state.ARCH_CODE_FRAMEWORK_VOCABULARY`：vm_protected / lua_scripted / encrypted_sqlite / yara_embedded），`match_guides` 支持列表字段成员匹配；知识库扩至 9 份（新增 vm_protected / lua_scripted_agent / encrypted_database / yara_embedded，提炼改写自本地参考包，非逐字搬运）。
- **Phase 1 Worker** 读取 `summary/` + `extracts/` → 输出 `artifacts/p1_*_{timestamp}.json` → 再提炼为 `summary/`。
- **Phase 2 Scheduler** 读取 summary，生成决策写入 `scheduler_decision`；HITL 由 `graph_nodes.approval_gate_node` 负责（LangGraph `interrupt()` 挂起，外层 CLI 以 `Command(resume=回复)` 恢复，CONFIRM / MODIFY 协议，3 次无效默认 CONFIRM）。
- **Phase 3 双轨制**（批次 A2 已落地 2026-10-10）：`phase3_dispatch` 调度节点读取 `scheduler_decision.proposed_topics`（为空时按 `behavior_profile.primary_type` 默认映射，如 Stealer→stealer+anti_analysis+command_dispatcher）+ 护栏修正后的候选函数，构建 `TaskManifest`（主题任务按归组启发式分配函数、未被覆盖候选逐个生成函数兜底任务、`depends_on` 依赖标注分两波），落盘 `meta/task_manifest.json` 并写入 state `task_manifest`；MODIFY 人工指定路径只产函数任务且**无条件采纳**（圈外地址合成 FuncCandidate 补入，修复 A1 过滤丢弃缺陷）。条件边 `phase3_fanout` 扇出 wave0（无依赖主题 → `Send("phase3_topic", {"analysis_task": ...})`，函数兜底 → `Send("phase3_function", {...})`），全部完成后 `phase3_wave2` 中继节点扇入触发，再由 `phase3_fanout_wave2` 扇出 wave1（有依赖主题 → `phase3_topic_dep`，前置主题摘要注入 prompt）；空任务直通 `verification_agent`。主题节点 `make_topic_node`：逐函数 `load_function_data` 聚合 → `build_topic_prompt`（五段式 + 8 主题方法论）→ `invoke_guarded` 单次主调用（不做 ReAct）→ `bb_write_artifact("topic_{topic}")` + extractor 摘要 `summary/topics/{topic}`；`bb_has_artifact` 幂等跳过。函数节点 `make_phase3_function_node` 逻辑不变：`bb_write_artifact`（`artifacts/phase3_func_{addr}.json`）→ extractor 提炼到 `summary/phase3_funcs/` → `bb_checkpoint`。并发上限由 `analysis.phase3_max_concurrency`（默认 4）控制，主题轨与函数轨各自独立 `asyncio.Semaphore`（主题数量少，峰值可控）；结果分别经 `topic_analysis_refs` / `func_analysis_refs` 的 `add` reducer 聚合。
- **orchestrator 质量编排**（批次 A3 已落地 2026-10-10）：`orchestrator_node`（纯代码，不调 LLM）位于两波 Phase 3 全部完成之后、`verification_agent` 之前。职责：① 把 wave0+wave1 的主题/函数产物渲染归档为 `data/output/docs/{project}/AGENT_XX_{主题}.md`（五要素：分析对象/执行时间/分析结论/关键引用/未解之谜，幂等续排）；② 五要素质量检查——产物缺关键字段（主题缺 findings/evidence、函数缺结论/行为/API）标记 `quality_failed` 记日志（不重试）；③ 缺口识别——manifest 任务 vs 实际 artifact，未完成的记入 `meta/gap_report.json`；④ 矛盾发现（保守启发式：两主题对同一函数地址的功能判定关键词类别不相交）→ 写入 `docs/{project}/USER.md` 编号待确认问题（同标题去重）；⑤ state 写 `orchestrator_report`（各项计数）。空任务时 dispatch 条件边直通 orchestrator（再进 verification_agent）。
- **USER.md 异步人机沟通**（批次 A3）：`tools/docs_tools.py` 维护 `docs/{project}/USER.md`（不存在时自动建骨架：编号问题列表 + "用户着重关心的内容"空段）。Agent 侧经 `user_md_append_question` 写入疑惑/矛盾（不阻塞执行流）；用户随时在问题的"用户回答："代码块中填入回答（Web UI"沟通记录"页签或直接编辑文件）。主题节点构建 prompt 前经 `user_md_read` 读取，把已回答问题与重点关注段拼为"特殊要求"注入 prompt——用户中途的回答从下一波主题分析开始生效。Web UI 接口：`GET /api/analysis/{project}/usermd`、`POST /api/analysis/{project}/usermd/reply`（只落盘，不影响图运行）。**C2 扩展**：`user_md_set_focus` 支持启动参数 focus/exclude 幂等落盘 focus 段，`_load_user_special_requirements(project, focus, exclude)` 把两个来源合并去重后统一注入 Worker/主题/函数/报告四类节点。
- **验证 Worker**（P2 已落地 2026-10-09）：`verification_agent`（WorkerSpec + `make_worker_node` 编译）收集 Phase 0-3 各 summary 的 high 置信度发现，经 `bb_read_summary` / `bb_list_artifacts` / `bb_read_artifact` 回查原始 artifact 证据，输出 `VerificationReport`（verified/disputed/unverifiable 三桶 + 理由）写入 `verification_report`；artifact 前缀 `p3v_`，summary 名 `verification_summary`。
- **Phase 4**：`shard_synthesis`（Map，每 5 个可疑函数一片，串行为小模型稳定性保留）→ `aggregator`（Reduce）读取所有 summary + shard_reports + **主题轨摘要**（`summary/topics/`，A2 遗留修复 2026-10-10），生成 `summary/p4_final_report.json`（新增 `topic_conclusions` 主题结论要点，仍受 ≤1500 tokens 硬限制）→ `report_generator`（P2 已落地 2026-10-09，**9 章化** 2026-10-10）汇总全部产出生成面向动态调试的 9 章 Markdown 综合参考手册（样本概览/执行流程/能力矩阵/函数速查/断点指南/全局变量/C2 提取/IoC/调试注意，对齐金标准 ALL_IN_ONE 骨架；章 5 直接消费 `behavior_profile.breakpoint_matrix`，章 6 用节点内 g_ 变量机器预扫描候选，章 7 消费反编译失败函数清单，章 8 直接引用 Phase -1 确定性分类产物；USER.md 的 focus/exclude 经 `_load_user_special_requirements` 拼接进 prompt 影响章节详略），落盘 `data/output/{project}/final_report.md`（不走 summary 1500 tokens 限制）+ `artifacts/p4_final_report_meta.json` 元数据，state 写 `report_md_path`。

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

其余运行时配置（模型、端点、路径、分析默认值）都在根目录 `config.yaml`，见 2.2 节。

### 4.2 运行方式

**CLI**

```bash
source .venv/bin/activate
# 输入放 data/input/ 下的 *_export_for_ai 目录，自动发现
python main.py \
    -p sample_001 \            # --project-name：data/output/ 子目录名
    # -i module.upx            # --input-name：可选，指定导出目录（可省略 _export_for_ai 后缀）
    # -r                       # --resume：可选，断点续跑
    # --focus "驻留,持久化"     # --focus：可选，用户重点关注领域（逗号分隔），优先详写
    # --exclude "加解密过程"    # --exclude：可选，用户排除领域，只保留动调提取方案
```

三个参数的默认值均取自 `config.yaml` 的 `analysis.*`（CLI 传参优先，环境变量 `PROJECT_NAME` / `INPUT_NAME` / `RESUME` 兜底，focus/exclude 对应 `FOCUS` / `EXCLUDE`）；`config.yaml` 配好 `analysis.project_name` 后可直接 `python main.py` 无参运行。输入目录解析规则：显式 `-i` > project-name 前缀匹配 > 唯一候选自动选用。不再需要 `--export-dir` / `--work-dir` / `--sample-type`：样本类型永远 auto，由 `pre_extract` 节点调 `detect_sample_type` 判定。

**Web UI（审查面板）**

```bash
python -m webui.server    # 从项目根目录启动；默认 127.0.0.1:8300
                          # 地址/端口取 config.yaml 的 webui.host / webui.port（env: WEBUI_HOST / WEBUI_PORT）
```

浏览器打开 `http://127.0.0.1:8300/` 即可：启动分析 → 轮询状态 → 审批门可视化审查（CONFIRM / MODIFY 勾选函数地址）→ 渲染最终 Markdown 报告。人工协作面板含"人工审批 / 沟通记录"两个页签：沟通记录页签展示 `docs/{project}/USER.md` 中的 Agent 提问并可逐条回复（异步通道，提交只落盘不影响图运行）。图状态复用 `data/output/{project}/checkpoints.db`（thread_id = 项目名），服务重启后输入项目名点"查询/接管现有项目"恢复审批。后端复用 `main.py` 抽出的公共函数（`make_saver_cm` / `collect_pending_interrupts` / `resolve_sample_export_dir`），CLI 行为不变。

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
- **路径**：使用 `pathlib.Path` 或 `os.path.join`，跨平台兼容；黑板路径全部基于当前工作目录下的 `data/output/`（由 `tools.blackboard_tools.board_base_dir()` 决定，读 `config.yaml` 的 `paths.output_root`，环境变量 `BOARD_BASE_DIR` 兜底）。
- **命名**：
  - Worker 模块：`{purpose}_{role}.py`，WorkerSpec `name` 与模块名一致。
  - `output_key` 规范：`string_analysis`、`api_behavior_analysis`、`export_interface_analysis`、`behavior_profile`、`function_boundary_analysis`、`scheduler_decision`、`verification_report`；Phase 4 聚合结果不落 state 原文，只写 `final_report_ref`（`bb://summary/p4_final_report`）；Markdown 手册路径写 `report_md_path`。
  - 黑板 summary 名：`strings_summary`、`api_summary`、`exports_summary`、`behavior_summary`、`functions_summary`、`p2_decision`、`verification_summary`、`p4_final_report`；Phase 3 扇出摘要带目录前缀：`phase3_funcs/func_{addr}`（函数轨）、`topics/{topic}`（主题轨）。
- **Token 预算**：
  - 所有 agent 单次 LLM 调用输入上限 128k tokens（`MAX_CONTEXT_TOKENS` 可覆盖）：Worker ReAct 循环由 `SummarizationMiddleware` 在 75% 阈值触发摘要压缩；extractor / Phase 3 / Phase 4 的直接调用统一走 `graph_nodes.invoke_guarded`（超限先头尾保留式截断，仍超限抛 `RuntimeError`）；
  - 单次分析总 token 预算（B1）：`analysis.token_budget`（env `TOKEN_BUDGET`，null=不启用）。启用后每次 LLM 调用前经 `graph_nodes._enforce_token_budget` 检查项目累计用量（数据源：`observability` 模块级 callback 注册表），超限 `interrupt({"kind": "token_budget", ...})` 挂起等人工；resume 后阈值自增一个步长（=基础预算），再次超再挂起，可反复放行；
  - Worker 输出 artifact 无明确上限；
  - Extractor 产出 summary 必须 ≤1500 tokens（`blackboard_tools.bb_write_summary` 会硬拦截）；
  - Phase 3 函数分析 prompt 要求模型输出 ≤1000 tokens。
- **置信度等级**：`high` / `medium` / `low`。`high` 必须有明确、无歧义的证据；不允许猜测不存在的数据。

---

## 6. 测试策略

- **单元测试**：
  - `test_tools.py`：验证 `file_loaders`/`pe_utils` 对正常/缺失输入的处理。
  - `test_b2_preextract.py`（B2）：验证预提取加码（字符串 8 类分类 / API 功能分类，合成数据）、函数四桶分桶（合成 + 真实 fixture：exports 桶含 ordinal_1/2、library_suspect 含 0x1800B0160）、load_* 工具产物优先与回退兼容、fallback 标注与 prompt 专项段切换。
  - `test_blackboard_tools.py`：验证 summary 大小限制、checkpoint、artifact 存在性、日志追加。
  - `test_docs_tools.py` / `test_orchestrator.py`：验证 docs 归档层五要素渲染与读写、USER.md 骨架/编号问题/回答追加，orchestrator 节点的质量检查/缺口识别/矛盾发现/幂等与 USER.md prompt 注入。
  - `test_workers.py` / `test_extractor.py` / `test_phase3.py` / `test_phase4.py`：验证 WorkerSpec 存在、名称、output_key、prompt 包含必要字段；`test_phase4.py` 另覆盖 9 章手册 prompt 断言、主题摘要进入 shard/aggregator/report_generator 输入、breakpoint_matrix 消费、USER.md 注入、空数据兜底 9 章齐全 + `tools/benchmark.compare` 章节维度满分。
  - `test_knowledge.py`：验证知识库注册表（含 C1 新增的 4 份框架指南一致性）、token 预算、`__active__` 解析、`match_guides` 路由（含 code_frameworks / packer_protector 列表成员匹配）。
  - `test_focus_exclude.py`（C2）：验证 focus/exclude 全链路——约束文案（"用户指示不深入分析此部分"/动调提取方案/不阻塞）、USER.md 落盘（`user_md_set_focus` 幂等追加）、两来源合并去重、Worker/主题/函数/报告四类注入点、CLI `--focus`/`--exclude` 转发、config.yaml 默认值、Web UI start 端点。
- **集成测试**：
  - `test_integration.py`：验证 `build_graph` 图结构、`graph.ainvoke` 端到端编排（假模型注入）、TokenStatsCallback 报告统计、approval_gate HITL 协议解析、预提取生成 `data/output/` 目录结构、上下文预算截断。
  - `test_model_tiering.py`（B1）：验证模型分层——WorkerSpec tier 声明、`get_llm(tier)` 双单例缓存与 light 缺省回退 strong、节点工厂按 tier 取模型（extractor 固定 light）、`build_graph(llm=fake)` 注入时分层不生效。
  - `test_token_budget.py`（B1）：验证 token 预算闸门——observability 注册表、`_enforce_token_budget` 的 interrupt/resume/步进语义（再次超再挂起）、`invoke_guarded` 与 Worker 节点入口接线。
  - `test_fault_tolerance.py`：验证失败后的状态恢复和摘要大小拒绝。
- **Fixture**：`data/input/module.upx_export_for_ai/` 提供真实的 IDA 导出数据，用于测试 `pre_extract_sample`、`load_function_data` 和目录结构。缺失时自动跳过。
- **Mock**：LLM 调用在测试中全部通过假模型完成（`graph_nodes.set_llm(fake)` 或 `build_graph(llm=fake)`，配合 LangChain `FakeListChatModel` / 自定义 fake chat model），**不会在测试里消耗真实 API token**。

---

## 7. 安全与操作注意事项

- **恶意样本**：项目是分析工具，但当前实现只处理**静态文本导出**，不会执行原始二进制。不要在本项目代码中引入自动执行样本或自动下载 Payload 的逻辑。
- **API Key**：`.env` 已加入 `.gitignore`，Agent 不应读取或修改 `.env`；若需要新增环境变量，应提醒用户在本地 `.env` 中自行配置。
- **HITL（人在回路）**：Phase 2 结束后 `approval_gate` 节点通过 LangGraph `interrupt()` 挂起（图状态由 checkpointer 持久化，默认 `data/output/{project}/checkpoints.db` 的 AsyncSqliteSaver），CLI 打印审批负载后读取人工回复并以 `Command(resume=...)` 恢复，必须回复 `CONFIRM` 或 `MODIFY <addr1>,<addr2>,...` 才会继续 Phase 3（3 次无效输入默认 CONFIRM 放行）。不要绕过该节点自动继续。
- **数据残留**：运行时会生成 `data/output/`、`.pytest_cache/`。`data/` 与 `.pytest_cache/` 均已 gitignore，部署或打包时无需包含。
- **URL/IOC 处理**：Worker 可能从样本中提取 C2 URL、文件路径等敏感 IoC。黑板中的 artifact/summary 应被视为敏感分析数据，按组织安全策略保管。

---

## 8. 当前已知问题与开发陷阱

> 以下内容基于当前代码实际状态，Agent 在修改前应特别注意。

1. ~~编排层历史债务~~ —— **已通过 LangGraph 迁移根治**（2026-09-22）：Phase 0→4 全部统一在 `graph.py` 的单一 `StateGraph` 中，阶段门控 checkpoint 与 HITL 审批门都是普通节点，不再有手写 Runner 循环。

2. ~~HITL 与框架回调耦合~~ —— **已通过 LangGraph 迁移根治**（2026-09-22）：HITL 是 `approval_gate` 普通节点，`graph.py` 完全控制 Phase 2→3 流转。Step 2 已落地（2026-10-09）：审批门改为 `interrupt()` 挂起 + `Command(resume=...)` 恢复，图状态由 AsyncSqliteSaver 持久化到 `data/output/{project}/checkpoints.db`；`-r/--resume` 仍是黑板层断点（跳过 Phase -1），与图级 checkpointer 互补。

3. ~~Worker 提示词幻觉风险~~ —— **已缓解**（2026-06-09）：全部 Worker 增加数据充足性检查、证据链约束、最简 schema（2层嵌套上限）、具体反幻觉规则。

4. **测试的 cwd 敏感性**
   - 黑板测试和预提取测试会 `os.chdir(tempdir)`。Windows 下临时目录句柄可能未释放，测试里已经设置 `ignore_cleanup_errors=True`；本地运行若遇到权限错误，通常是杀毒软件或文件句柄未释放，重试即可。

---

## 9. 常用扩展点

| 需求 | 推荐修改位置 |
|------|-------------|
| 调整全局配置（模型/路径/分析默认值） | 直接编辑根目录 `config.yaml`；新增配置项在 `config.py` 用 `cfg()` 读取 |
| 新增一个 Phase 0/1 Worker | `workers/phaseX/` 新增提示词模块，在 `workers/specs.py` 声明 WorkerSpec，在 `graph.py` 加节点与边 |
| 调整 Worker 提示词 | 直接修改对应 `workers/phaseX/xxx.py` 中的 `INSTRUCTION` 常量（无需动 specs.py） |
| 新增文件加载 Tool | `tools/file_loaders.py` 实现，加入对应 `workers/specs.py` 中 WorkerSpec 的 `tools` 元组 |
| 修改黑板目录结构 | `tools/blackboard_tools.py` 中的 `board_base_dir` 和 `_ensure_dirs`；docs 归档目录在 `tools/docs_tools.py` 的 `docs_dir` |
| 新增样本类型（LNK/ELF） | 新增 `workers/optional/` 提示词 + spec，在 `detect_sample_type` 和 `graph.py` 中动态加载 |
| 新增知识指南文件 | `workers/knowledge/` 新增带 frontmatter 的 .md（name/applies_to/priority/max_tokens ≤1200）；applies_to 标签对应 `arch_detection` 字段（列表字段按成员匹配），注册表 import 时自动构建 |
| 修改 Token 统计字段 | `tools/token_stats.py` 中的 `StageTokenStats` / `AnalysisTokenReport`；节点归属逻辑在 `observability.py` |
| 调整图结构 / 编排 | `graph.py`（加边/加节点）与 `graph_nodes.py`（节点工厂与业务节点实现） |

---

## 10. 参考资料

- `ARCHITECTURE.md`：项目架构指南（中文），包含 LangGraph 图示、Worker 职责、AnalysisState 字段规范、扩展路线图。
- `docs/RevAgent_LangGraph迁移方案.md`：ADK → LangGraph 迁移方案，记录了新架构的设计决策。
- `docs/architecture/`：历史架构图示（HTML/PNG），仅供参考，可能与当前实现有出入。
