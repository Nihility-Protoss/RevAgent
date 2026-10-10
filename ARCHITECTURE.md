# RevAgent — Architecture Guide

> **版本**: 3.0 (LangGraph 迁移版)  
> **框架**: LangGraph 1.x `StateGraph`（`langgraph>=1.0`）  
> **适用范围**: 基于 IDA 无 MCP 导出文件的 Windows PE 恶意样本静态分析  
> **历史**: 本项目原基于 Google ADK（`google.adk.workflow.Workflow`），已完成迁移至 LangGraph，迁移方案见 `docs/RevAgent_LangGraph迁移方案.md`。

---

## 1. 概述

本 Agent 是一个基于 LangGraph 的恶意样本深度分析系统。核心设计原则是：

1. **静态分析为主**：输入数据来自分析师人工导出的 IDA 反编译/反汇编文件，不直接解析原始二进制
2. **分阶段递进**：Phase -1 预提取 → Phase 0 快速定性 → Phase 1 行为定型 → Phase 2 调度审查 → Phase 3 双轨制深度分析（主题轨 + 函数轨）→ orchestrator 质量编排（docs 归档 + 质量/缺口/矛盾检查）→ 验证 Worker（证据回查）→ Phase 4 综合报告 → 综合参考手册（Markdown）
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
approval_gate（HITL：interrupt() 挂起，CLI 读取回复后 Command(resume=...) 恢复；
             CONFIRM / MODIFY addr,...；3 次无效默认 CONFIRM）
                     │
                     ▼
phase3_dispatch（调度：构建 TaskManifest（主题任务+函数兜底+依赖分波），
              落盘 meta/task_manifest.json）
                     │（条件边：wave0 任务每个一个 Send；空任务直通 verification_agent）
                     ▼
Phase 3 双轨制（批次 A2，2026-10-10 落地）：
  ┌────────────────────────────┬────────────────────────────┐
  ▼                            ▼
phase3_topic（主题轨：无依赖    phase3_function（函数轨：未被
  主题任务，一主题一次主调用，    主题覆盖的候选逐函数分析，
  bb_has_artifact 幂等跳过）     bb_has_artifact 幂等跳过；
  │                            │并发上限 analysis.phase3_max_concurrency=4）
  └────────────────────────────┼────────────────────────────┘
                               ▼
phase3_wave2（中继：wave0 全部完成后扇入触发）
                     │（条件边：wave1 有依赖主题 Send 扇出；空则直通）
                     ▼
phase3_topic_dep（第二波主题：depends_on 前置主题摘要注入 prompt）
                     │
                     ▼
orchestrator（Phase 3 后置质量编排，纯代码不调 LLM：
            wave0+wave1 产物归档 docs/{project}/AGENT_XX_{主题}.md 五要素；
            五要素质量检查 quality_failed 标记；缺口识别 meta/gap_report.json；
            矛盾发现启发式 → USER.md 待确认问题；state 写 orchestrator_report）
                     │
                     ▼
verification_agent（验证 Worker：回查 high 置信度发现的原始 artifact 证据，
                  verified / disputed / unverifiable 三分类 → verification_report）
                     │
                     ▼
shard_synthesis（Map：每 5 个可疑函数一片，串行分片为小模型稳定性保留；
              输入含主题轨摘要 summary/topics/）
                     │
                     ▼
aggregator（Reduce：汇总 shard_reports + 主题摘要 → summary/p4_final_report
          （含 topic_conclusions 主题结论要点，≤1500 tokens 硬限制））
                     │
                     ▼
report_generator（综合报告 Worker：9 章 Markdown 参考手册（样本概览/执行流程/
                能力矩阵/函数速查/断点指南/全局变量/C2 提取/IoC/调试注意），
                消费主题摘要 + breakpoint_matrix + 预提取分类产物 + USER.md 特殊要求，
                落盘 data/output/{project}/final_report.md + artifacts/p4_final_report_meta.json）
                     │
                     ▼
END
```

> Phase 3 双轨制（批次 A2）已落地（2026-10-10）：`phase3_dispatch` 构建 `TaskManifest`（主题任务 + 函数兜底 + `depends_on` 依赖标注），条件边分两波 Send 扇出——wave0（无依赖主题 + 函数兜底）→ `phase3_wave2` 中继（扇入等全部完成）→ wave1（有依赖主题，`phase3_topic_dep`）。主题词表见 `state.ANALYSIS_TOPIC_VOCABULARY`（8 主题）。MODIFY 缺陷修复：人工指定的圈外地址无条件采纳（合成 FuncCandidate 补入）。Send 并行扇出（Step 3，2026-10-09）与 HITL `interrupt()` + checkpointer（Step 2）保持不变。
>
> docs 归档层 + USER.md 异步通道 + orchestrator 质量编排（批次 A3）已落地（2026-10-10）：`orchestrator` 纯代码节点位于两波 Phase 3 之后、`verification_agent` 之前（空任务时 dispatch/wave2 条件边直通 orchestrator），负责 AGENT_XX 五要素归档、质量检查、缺口识别与矛盾发现；`docs/{project}/USER.md` 为异步人机沟通文档，用户已回答内容在主题节点构建 prompt 前注入"特殊要求"段。

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
# ... Phase 1 扇出 → scheduler → approval_gate → phase3 → verification_agent → shard → aggregator → report_generator → END

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

- **`output_schema` 化**（2026-10-09 全覆盖）：全部 7 个 spec（5 worker + scheduler + verification）均已声明 Pydantic 模型——`state.py` 的 `StringAnalysis` / `ApiBehaviorAnalysis` / `ExportInterfaceAnalysis` / `BehaviorProfile` / `FunctionBoundaryAnalysis` / `SchedulerDecision` / `VerificationReport`，根治了 JSON 字符串状态问题；字段全部带默认值，`insufficient_data` 最小输出也能通过结构化解析。
- **行为定型关键产出**: P0/P1/P2 断点矩阵建议、8步分析 checklist 完成状态
- **函数排序维度**: xrefs 调用频率、thunk 排除、函数大小、入口点 proximity、命名暗示、**导出函数永远优先**（无条件列入并置顶，priority=10）、**运行时库函数识别**（xrefs 极高 + 无名 sub_ + 高地址尾部 + size 小的函数不得因 xref 高而置顶，priority ≤ 4）、**命令分发器置顶**（xrefs 高 + size 中等偏大 + 被导出函数调用）
- **候选代码级护栏**（A0，2026-10-10 落地）：`candidate_guards.apply_candidate_guards` 在 `_select_phase3_candidates` 中对 LLM 候选做确定性后置修正——导出函数强制置顶（缺席时合成条目补入，导出地址取 state 的 `export_interface_analysis`，兜底黑板 `extracts/exports_extract.json`）；疑似库函数排除（xrefs 超过 `analysis.lib_xref_threshold`（默认 50）+ 无名 sub_ + 地址位于样本函数地址范围尾部 `analysis.lib_tail_ratio`（默认 0.45）区间，size 未知不阻断，导出函数豁免）；其余候选按 `analysis_priority>=7` 降序补足 Top N（`analysis.phase3_top_n`，默认 20）。MODIFY 人工指定路径不经过护栏，且**无条件采纳**（A2 修复：圈外地址合成 FuncCandidate 补入，不再被候选过滤丢弃）

### 3.3 Phase 2: Scheduler + HITL

#### Scheduler Agent
- **职责**: 中央协调器，读取 5 个 summary，整合摘要，输出决策
- **定义**: `workers/phase2/scheduler.py` 的 `SCHEDULER_INSTRUCTION`，`workers/specs.py` 的 `scheduler` spec
- **输出键**: `scheduler_decision`
- **规则**: 只做数据路由和状态管理，不做样本分析推理

#### Human Review Gate（approval_gate）

- **位置**: `graph_nodes.py` 的 `approval_gate_node` 节点（Phase 2→3 之间）
- **触发时机**: Scheduler 完成后
- **交互方式**: 图内 `interrupt()` 挂起（负载含审查消息与错误提示）；`main.py` 的中断循环读取负载打印到 CLI、`input()` 读取回复后以 `Command(resume=回复)` 恢复；无效回复在节点内再次 `interrupt()`。图状态由 checkpointer 持久化（默认 `data/output/{project}/checkpoints.db` 的 AsyncSqliteSaver），进程重启后可用同一 thread_id（即项目名）恢复审批现场。
- **审查内容**: 行为定型结论、高风险字符串/API 指标计数、Top 20 候选函数
- **回复协议**:
  - `CONFIRM` — 同意继续，使用推荐候选函数（`analysis_priority >= 7` 的 Top 20）
  - `MODIFY <addr1>,<addr2>,...` — 指定要分析的函数地址列表，逗号分隔
  - 连续 3 次无法识别的回复后默认按 CONFIRM 放行
- **写入 state**: `phase2_human_decision`（str）、`human_approved_functions`（list[str]，MODIFY 时）

### 3.4 Phase 3：双轨制深度分析（批次 A2，2026-10-10）

对齐金标准（人工分析）Phase 2 的主题制：在原有逐函数分析之外新增**主题轨**，围绕分析主题聚合多函数上下文做跨函数综合（如命令分发器主题产出逐条命令语义）。

- **任务清单**：`phase3_dispatch_node` 调 `build_task_manifest` 构建 `TaskManifest`（`state.py`），落盘 `meta/task_manifest.json` 并写入 state `task_manifest`。
  - **主题来源**：`scheduler_decision.proposed_topics` 优先（去重保序、过滤词表外取值）；为空时按 `behavior_profile.primary_type` 查默认映射（`DEFAULT_TOPICS_BY_BEHAVIOR`，如 Stealer→stealer+anti_analysis+command_dispatcher）。
  - **归组启发式**（`_pick_topic_functions`，确定性无 LLM，注释详述）：强特征主题先分（command_dispatcher=导出∩候选+xrefs 降序、init_config_decrypt=size 降序、export_interface=全部导出），弱特征主题后分（priority 降序）；一个函数只归一个主题，每主题上限 `TOPIC_MAX_FUNCS=3`；归组为空的主题不立项。
  - **函数兜底**：未被任何主题覆盖的护栏后候选逐个生成函数任务（沿用 `phase3_function` 节点）。
  - **MODIFY 路径**只产函数任务：人工已精确圈定分析范围，不做主题归组。
- **依赖分波**：`TOPIC_DEPENDS_ON`（command_dispatcher/network_stack/stealer 依赖 init_config_decrypt——配置/密钥结论是前置上下文）；依赖目标不在本次清单时不标注。wave0（无依赖任务）由 `phase3_fanout` 扇出，`phase3_wave2` 中继节点扇入等全部完成后由 `phase3_fanout_wave2` 扇出 wave1；wave1 主题节点把前置主题的 extractor 摘要注入 prompt（数据流）。
- **主题节点**：`make_topic_node`（wave0=`phase3_topic`、wave1=`phase3_topic_dep` 共用工厂）：逐函数 `load_function_data` 聚合 → `build_topic_prompt`（`workers/topics/topic_prompts.py`，五段式 + 8 主题方法论要点）→ `invoke_guarded` 单次主调用（不做 ReAct，一主题一次主调用 + extractor 共 2 次 LLM 调用）→ `bb_write_artifact("topic_{topic}")` + extractor 摘要 `summary/topics/{topic}` → `bb_checkpoint`；`bb_has_artifact` 幂等跳过；并发信号量与函数轨各自独立取 `phase3_max_concurrency`（主题数量少，独立计数峰值可控，工厂零耦合）。
- **输出模型**：`TopicAnalysis`（status/topic/summary/findings/evidence/confidence/unresolved，嵌套 ≤2 层），节点结果经 `topic_analysis_refs`（`add` reducer）聚合。

### 3.5 Phase 3 后置：orchestrator 质量编排与 docs 归档层（批次 A3，2026-10-10）

对齐金标准人工协作 Skill 的父 Agent 职责（一切交流落盘归档），在两波 Phase 3 全部完成后、验证 Worker 之前执行一次。

- **节点**：`graph_nodes.orchestrator_node`（**纯代码，不调 LLM**，同步节点）。
- **图位置**: `phase3_topic_dep → orchestrator → verification_agent`（wave1 空时由 `phase3_wave2` 条件边直通 orchestrator；空任务时 `phase3_dispatch` 条件边直通 orchestrator）。
- **职责**：
  1. **docs 归档**：把 wave0+wave1 的主题/函数产物渲染为五要素 Markdown（分析对象/执行时间/分析结论/关键引用/未解之谜），落盘 `data/output/docs/{project}/AGENT_{seq:02d}_{主题}.md`（`tools/docs_tools.py`；幂等：同对象已归档跳过，序号从已有最大值续排）；
  2. **五要素质量检查**：产物缺关键字段（主题产物缺 findings/evidence，函数产物缺结论与行为/API；`insufficient_data` 合法豁免）→ 标记 `quality_failed` 并记日志（不重试，重试留给后续批次）；
  3. **缺口识别**：manifest 任务 vs 实际 artifact，未完成的记入 `meta/gap_report.json`；
  4. **矛盾发现（启发式）**：两主题对同一函数地址的功能判定关键词类别不相交（如一边判"解密"一边判"网络"）→ 写入 USER.md 编号待确认问题（同标题去重）。保守规则：双方类别集都非空且互不相交才报，只是"值得人工看一眼"的提示，不自动裁决；
  5. **state 写入** `orchestrator_report`（docs_written / quality_failed / gaps / contradictions 及其计数）。
- **USER.md 异步人机沟通**：`docs/{project}/USER.md`（不存在时自动建骨架：编号问题列表 + "用户着重关心的内容"空段）。Agent 运行中写入疑惑/矛盾**不阻塞执行流**；用户经 Web UI"沟通记录"页签或直接编辑文件，在问题的"用户回答："代码块中填入回答（追加语义，保留历史）；主题节点构建 prompt 前经 `_load_user_special_requirements` 读取，把已回答问题与重点关注段拼为"特殊要求"注入主题 prompt——中途回答从下一波主题分析开始生效。Web UI 接口：`GET /api/analysis/{project}/usermd`、`POST /api/analysis/{project}/usermd/reply`。

### 3.6 Phase 3 后置：验证 Worker（verification_agent）

- **职责**: 收集 Phase 0-3 各 summary 中的 high 置信度发现，经黑板工具回查原始 artifact 证据，识别幻觉与过度推断；不做新的分析推理
- **定义**: `workers/phase3/verification_agent.py` 的 `VERIFICATION_AGENT_INSTRUCTION`（五段式），`workers/specs.py` 的 `verification_agent` spec（WorkerSpec + `make_worker_node` 编译，artifact 前缀 `p3v_`，summary 名 `verification_summary`）
- **输出键**: `verification_report`（`VerificationReport` Pydantic 模型：`verified` / `disputed` / `unverifiable` 三桶 + 理由；`model_validator` 容错地把扁平 `findings` 列表按 `verdict` 归桶，词表外取值一律归入 `unverifiable`）
- **图位置**: `orchestrator → verification_agent → shard_synthesis`（wave1 空时由 `phase3_wave2` 经 orchestrator 直通）；空任务时 `phase3_dispatch` 条件边经 orchestrator 直通（验证覆盖 Phase 0-2，不跳过）

### 3.7 Phase 4 收尾：综合报告 Worker（report_generator）

- **职责**: 汇总全部 summary + shard_reports + verification_report + p4_final_report + 主题轨摘要，生成面向动态调试的 **9 章** Markdown 综合参考手册
- **定义**: `workers/phase4/report_generator.py` 的 `REPORT_GENERATOR_PROMPT`（五段式，纯 Markdown 输出），由 `graph_nodes.make_report_generator_node` 编译为普通节点（单次 `invoke_guarded` 调用，非 WorkerSpec——数据已在节点内直接收集，无需 ReAct 工具循环）
- **9 章结构**（2026-10-10 落地，对齐金标准 ALL_IN_ONE 骨架；`tools/benchmark.py` 的章节维度据此评分）：`1. 样本概览 / 2. 完整执行流程图 / 3. 操作能力矩阵（驻留/持久化/注入/窃取/C2）/ 4. 关键函数速查表 / 5. 动态分析断点指南 / 6. 内存中的关键全局变量 / 7. C2 与配置提取方法 / 8. IoC 指标汇总 / 9. 调试注意事项`；每章末尾标注整体置信度，无数据章保留标题并标注缺口（禁止删章/编造）
- **章节数据源映射**（写进 prompt，模型按字段搬运）：章 1/2 ← Phase 0/1 summary + `behavior_profile`（state 原文优先，含 execution_chain_skeleton）；章 3 ← `topic_summaries` + verification_report；章 4 ← 护栏候选 + phase3_funcs 摘要 + orchestrator_report；章 5 ← `behavior_profile.breakpoint_matrix`（P0/P1/P2 结构化建议直接消费）；章 6 ← `global_var_candidates`（节点内对主题 artifact + 函数摘要机器预扫描 g_ 前缀变量，空则标"未发现"）；章 7 ← 解密/配置主题结论 + `decompile_failed_functions`（反编译失败函数，断点+内存观察方案）；章 8 ← `preclassified_iocs`（Phase -1 确定性分类产物，每类截断前 10 条）；章 9 ← anti_debugging + anti_analysis 主题 + unresolved/gaps 汇总
- **主题摘要消费**（A2 遗留修复，2026-10-10）：`_read_topic_summaries`（`bb_list_summaries("topics/")`）接入 shard_synthesis / aggregator / report_generator 三个节点的输入；aggregator 的 `p4_final_report` 新增 `topic_conclusions` 主题结论要点（提炼≤10 条，仍受 summary ≤1500 tokens 硬限制）
- **USER.md 注入**：节点复用 `_load_user_special_requirements` 读取用户 focus/已回答问题，拼接进 user 消息——focus 维度优先详写，exclude 维度只保留动调提取方案不展开静态过程
- **落盘**: `data/output/{project}/final_report.md`（正文不走 summary 的 1500 tokens 硬限制）；`artifacts/p4_final_report_meta.json` 存 JSON 元数据（路径/来源引用/生成时间）
- **图位置**: `aggregator → report_generator → END`

### 3.8 知识指南注入（Phase 0→1 门控）

- **来源**: Phase 0 字符串分析输出 `arch_detection`（架构/语言/加载方式/**框架引擎**，C1 起新增 `code_frameworks` 多值字段，词表见 `state.ARCH_CODE_FRAMEWORK_VOCABULARY`：vm_protected / lua_scripted / encrypted_sqlite / yara_embedded；string_artifact_analyst 的 arch_detection 维度内含各框架字符串特征速查：rustc 路径 / go.buildid / luaL_newstate / sqlite3_open / yr_compiler_create 等）。
- **路由**: `graph_nodes.resolve_guides_node` / `resolve_active_guides` 读取图状态中 `string_analysis.arch_detection`，匹配 `workers/knowledge/` 知识库，将激活的指南元数据写入 `meta/active_guides.json`。`match_guides` 对列表字段（code_frameworks / packer_protector）按成员匹配（C1）。
- **知识库清单**（C1 扩容后 9 份，均为提炼改写的项目自有文件，每份 ≤1200 tokens 由测试硬约束）：`windows_pe`（baseline，priority 10）、`file_loader_triage`（80）、`cpp` / `golang` / `rust`（90）、`vm_protected` / `lua_scripted_agent` / `encrypted_database` / `yara_embedded`（100，框架/引擎专项）。
- **消费**: Phase 1 经 `load_arch_guide("__active__")` 按需加载激活指南并注入 prompt；Phase 3 由 `_load_active_guides_text` 拼接全文注入函数分析 prompt。
- **默认回退**: `arch_detection` 缺失或 confidence=low 时回退到默认指南 `windows_pe`。

### 3.9 focus/exclude 用户分析优先级（C2，2026-10-10）

对齐金标准的核心交互：用户声明重点关注领域（focus，如"驻留/持久化/二次加载/窃取"）与排除领域（exclude，如"加解密过程"），Agent 严格遵守——focus 优先详写，exclude 不深入静态过程、标注边界、只提供动调提取替代方案。

- **入口**: CLI `--focus` / `--exclude`（逗号分隔原文）> `config.yaml` 的 `analysis.focus` / `analysis.exclude` > 环境变量 `FOCUS` / `EXCLUDE`；Web UI start 端点请求体同名字段（缺省回退 config.yaml）。
- **传递**: 写入 `initial_state` 的 `user_focus` / `user_exclude`（`AnalysisState` 字段）；`pre_extract` 节点（fresh 分支）经 `_sync_user_priority_to_user_md` → `docs_tools.user_md_set_focus` 幂等落盘 USER.md"用户着重关心的内容"段（resume 跳过，不覆盖用户中途编辑）。
- **注入**: `graph_nodes._load_user_special_requirements(project, focus, exclude)` 统一汇总两个来源（USER.md focus 段 + 已回答问题、启动参数），按原文子串去重；`build_user_priority_text` 渲染约束文案。四类注入点：全部 Worker（`make_worker_node` task 消息）、主题节点（`build_topic_prompt(special_requirements=...)`）、函数节点（`build_func_analysis_prompt(special_requirements=...)`，最高优先级约束段）、报告节点（拼进 user 消息，影响章节详略）。Send 扇出为部分状态，`_task_base_payload` 显式透传 user_focus/user_exclude。
- **exclude 约束文案**（对齐金标准）：①不展开静态实现细节分析，不阻塞整体分析流程；②产物涉及处统一标注"用户指示不深入分析此部分"并说明边界；③结果性数据（密钥/配置明文/载荷）只提供动态调试提取方案（断点位置、观察方法、预期数据）。

---

## 4. FunctionTool 清单

Worker 的工具面从旧的 ALL_TOOLS 全量注入收敛为每个 WorkerSpec 声明的 2–4 个最小工具：

| 工具名 | 功能 | Worker 使用者 |
|-------|------|-------------|
| `load_strings` | 加载并分类 `strings.txt`（B2：传 `project_name` 且 `extracts/strings_categorized.json` 存在时优先返回 8 类分类产物，否则回退原始解析） | String Analyst, API Profiler |
| `load_exports` | 加载 `exports.txt`，构建 ordinal 映射 | Export Analyzer, Function Detector |
| `load_imports` | 加载 `imports.txt`，API 分类（B2：优先读 `extracts/imports_categorized.json` 功能类产物） | API Profiler |
| `load_function_index` | 加载 `function_index.txt`（B2：优先读 `extracts/functions_buckets.json` 四桶分桶产物，可按桶取数） | Export Analyzer, Function Detector |
| `bb_read_extract` | 读取黑板 `extracts/` 预提取分片 | 全部 Phase 0/1 Worker |
| `bb_read_summary` | 读取黑板 `summary/` 摘要 | Behavior Synthesizer, Scheduler, Verification Worker |
| `bb_read_artifact` | 读取黑板 `artifacts/` 完整 artifact 原文 | Verification Worker |
| `bb_list_artifacts` | 按前缀列出 `artifacts/` 名称（不含 latest/ 索引） | Verification Worker |
| `load_arch_guide` | 加载知识指南（`load_knowledge` 的别名工具） | Function Detector |
| `load_pe_info` | 加载预生成的 `pe_info.json` | —（预留） |
| `detect_sample_type` | 基于导出文件判断样本类型 | `pre_extract` 节点直接调用（非 Worker 工具） |
| `calculate_entropy` | 计算 Shannon 熵 | —（预留） |

> 黑板写入类工具（`bb_write_artifact` / `bb_write_summary` / `bb_checkpoint` / `bb_log_event` / `load_function_data`）不暴露给 Worker Agent，由节点函数（`make_worker_node` / `make_phase3_function_node` / `make_topic_node` / Phase 4 节点）在 LLM 调用之外直接调用，负责 artifact/summary 持久化与断点。docs 归档层（`tools/docs_tools.py` 的 `docs_write_agent_report` / `docs_read_agent_reports` / `user_md_*`）同样不暴露给 Worker，由 `orchestrator_node` / 主题节点 / Web UI 端点直接调用。
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

#### 4.1.1 Phase -1 预提取产物清单（extracts/）

`pre_extract_sample` 产出的全部黑板分片（`data/output/{project}/extracts/`）：

| 产物 | 内容 | 备注 |
|------|------|------|
| `strings_extract.json` | 字符串按类型/粗类别分组 + 100 条分片 | 既有 |
| `imports_extract.json` | DLL→API 映射与扁平列表 | 既有 |
| `exports_extract.json` | 导出地址/名列表 | 既有 |
| `functions_extract.json` | 函数索引全量（name/address/size/xrefs_count/**type**）+ 100 条分片 | B2 起解析 `Type:` 字段（`decompile` / `disassembly-fallback`） |
| `functions_manifest.json` | 地址 → decompile/disassembly 文件映射（文件名大小写兼容查找） | 既有（B2 起大小写不敏感） |
| `strings_categorized.json` | **B2**：字符串 8 类单归属分类（pdb_paths / urls / ips / registry_paths / command_lines / mutex_candidates / file_paths / domains），计数 + 明细 | 纯正则零 token |
| `imports_categorized.json` | **B2**：API 按功能类单归属（injection / anti_debug / crypto / network / registry / file / process / other），计数 + 明细，兼容 DLL 分节与 `addr:name` 两种格式 | 纯关键词匹配零 token |
| `functions_buckets.json` | **B2**：函数四桶分桶（exports > named > library_suspect > other，与 `candidate_guards` 同款规则同阈值），桶内明细带 `decompile_failed` 标记，`rules` 字段随盘记录阈值与 tail_start | 纯代码零 token |

#### 4.1.2 反编译失败 fallback 路由（B2，2026-10-10）

加壳/混淆样本中部分函数 IDA 反编译失败（`decompile_skipped.txt` 库函数跳过清单、`disassembly_fallback.txt` 回退清单），只有反汇编片段。机制：

- **标注**：`load_function_data` 返回 `decompile_failed`（伪代码缺失即 True，数据行为不变）；`function_index` 的 `Type: disassembly-fallback` 同步透传到 `functions_extract.json` 与 `functions_buckets.json` 明细。
- **prompt 切换**：`build_func_analysis_prompt` 检测到 `decompile_failed` 时追加 `DISASM_FALLBACK_SECTION`（反汇编专项段）；`build_topic_prompt` 对 fallback 函数块标题标记"（反编译失败，只有反汇编）"，且主题内只要含一个 fallback 函数即注入一次专项要求。
- **专项要点**（源自 `workers/knowledge/windows_pe.md` / `file_loader_triage.md` 既有方法论，不逐指令还原算法）：API 调用序列（call 目标，ror/rol 0x0D 哈希循环判动态解析）、常量与魔数（XOR 密钥、RC4/AES S 盒、cmp+跳转表命令分发）、字符串缓冲区写入地址（写后紧跟 MZ/4D 5A 比较 = 解密完成点）、循环结构语义（边界与步长）、动调断点建议（API 调用点/解码循环出口/缓冲区写完成点）。
- 金标准样本中核心函数 ordinal_1（`0x180013d80`）即 fallback 函数（`decompile returned None`），走该路径分析。

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
| `user_focus` | str | C2 用户重点关注领域（--focus 原文；pre_extract 落盘 USER.md，Send 载荷显式透传） |
| `user_exclude` | str | C2 用户排除领域（--exclude 原文；链路同 user_focus） |

**Worker 结构化输出**（WorkerSpec `output_key` 同名直译，dict 或 Pydantic model_dump）：

| 字段 | 写入节点 | 读取者 |
|------|---------|--------|
| `string_analysis` | string_artifact_analyst | resolve_guides、approval_gate、Phase 4 |
| `api_behavior_analysis` | api_behavior_profiler | approval_gate、Phase 4 |
| `export_interface_analysis` | export_interface_analyzer | Phase 4 |
| `behavior_profile` | behavior_profile_synthesizer | approval_gate、Phase 4 |
| `function_boundary_analysis` | function_boundary_detector | approval_gate、phase3_dispatch |
| `scheduler_decision` | scheduler | 外部接口 |

**HITL / Phase 3/4**：

| 字段 | 类型 | 写入节点 | 说明 |
|------|------|---------|------|
| `phase2_human_decision` | str | approval_gate | `CONFIRM` 或 `MODIFY ...` 原文 |
| `human_approved_functions` | list[str] | approval_gate | MODIFY 指定的函数地址列表（无条件采纳，圈外地址合成 FuncCandidate） |
| `task_manifest` | dict | phase3_dispatch | TaskManifest model_dump（主题任务+函数兜底+依赖分波；meta/task_manifest.json 同步落盘） |
| `func_analysis_refs` | `Annotated[list[dict], add]` | phase3_function（Send 扇出，每函数一条引用） | 逐函数分析结果引用（reducer 聚合） |
| `topic_analysis_refs` | `Annotated[list[dict], add]` | phase3_topic / phase3_topic_dep（Send 扇出，每主题一条引用） | 主题分析结果引用（reducer 聚合） |
| `verification_report` | dict | verification_agent | high 置信度发现验证结论（verified/disputed/unverifiable 三桶，VerificationReport model_dump） |
| `orchestrator_report` | dict | orchestrator | 质量编排报告：docs_written / quality_failed / gaps / contradictions 及计数（A3） |
| `shard_reports` | `Annotated[list[dict], add]` | shard_synthesis | 分片综合报告（reducer 聚合） |
| `final_report_ref` | str | aggregator | 固定为 `bb://summary/p4_final_report` |
| `report_md_path` | str | report_generator | Markdown 综合参考手册落盘路径（`data/output/{project}/final_report.md`） |

### 5.2 Token 统计

`observability.py` 的 `TokenStatsCallback(BaseCallbackHandler)` 挂在 LangChain callback 上，按 `langgraph_node` metadata 将每次 LLM 调用归并到所属图节点，**覆盖全部阶段（含 Phase 3/4）**。聚合结果为 `tools/token_stats.py` 的 `AnalysisTokenReport`（`add_usage(stage_name, prompt, candidate, total)`，输出格式与旧版 `to_dict()` 兼容）。

模块级注册表（B1）：`register_callback(project_name, callback)` 在 `main.py`（CLI）与 `webui/server.py` 的推进任务创建 callback 时调用；`current_total_tokens(project_name)` 返回项目实时累计 total tokens（未注册返回 0），是 token 预算闸门（5.4）的数据源。注意 Web UI 分段推进时计数按单次推进累计，跨推进（审批恢复后）的历史用量不继承。

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

### 5.4 模型分层与 Token 预算闸门（B1，2026-10-10）

**模型分层**：轻任务可用小模型降本。`config.yaml` 的 `llm.light_model` / `light_base_url` / `light_api_key`（env `LIGHT_MODEL` / `LIGHT_BASE_URL` / `LIGHT_API_KEY` 兜底）配置轻任务模型；`light_model` 缺省（null）时 `get_llm("light")` 直接返回 strong 单例，零行为变化。`get_llm(tier)` 双单例缓存（`_LLM` / `_LLM_LIGHT`）。分层默认：

| tier | 节点 |
|------|------|
| **light** | 3 个 Phase 0 triage Worker、scheduler、verification_agent、extractor 摘要调用（`run_extraction`） |
| **strong** | 2 个 Phase 1 Worker、Phase 3 主题节点（`make_topic_node`）、Phase 3 函数节点（`make_phase3_function_node`）、shard_synthesis、aggregator、report_generator |

Worker 侧由 `WorkerSpec.tier` 声明（`"light"` / `"strong"`，默认 strong），`make_worker_node` 按 `spec.tier` 取主调用模型、extractor 固定取 light；主题/函数/Phase 4 节点工厂签名为 `make_xxx_node(llm=None, tier="strong")`。`llm` 显式传入（`build_graph(llm=fake)` / `set_llm(fake)` 测试注入）时所有 tier 都用注入模型，`get_llm` 不被调用。

**Token 预算闸门**：`analysis.token_budget`（env `TOKEN_BUDGET`，null=不启用）限制单次分析总 token。启用后：

- **检查点**：所有直接 LLM 调用的统一入口 `invoke_guarded(..., project_name=...)` 调用前先过 `_enforce_token_budget`；Worker ReAct 内层调用不经 invoke_guarded，故 `make_worker_node` 在主调用 `ainvoke` 前加同样检查。
- **挂起**：项目累计用量（`current_total_tokens`）达到 `基础预算 + 已放行额度` 时 `interrupt({"kind": "token_budget", "used_tokens": ..., "budget": ..., "effective_budget": ...})` 挂起等人工。
- **步进放行**：resume（任意文本，CLI 中断循环与 webui decision 端点都透传）后 `_BUDGET_ALLOWANCE[project] += 基础预算`（模块级记录，节点重跑不丢失）；用量再次涨满一个步长会再次挂起，可反复放行。
- **Web UI**：decision 端点对 CONFIRM/MODIFY 之外的任意非空字符串原样透传为 resume 文本；前端对 `kind == "token_budget"` 的挂起显示"继续"按钮（发送 `CONTINUE`）。

---

## 6. 目录结构

```
multi-agent-adk/
├── main.py                           # 运行时入口：CLI 参数解析 + run_analysis_with_blackboard
├── graph.py                          # 唯一编排定义处：build_graph(llm, checkpointer) StateGraph 组装
├── graph_nodes.py                    # 节点工厂与业务节点：make_worker_node / pre_extract /
│                                     #   resolve_guides / approval_gate / phase3 / orchestrator /
│                                     #   verification / shard / aggregator / report_generator
├── candidate_guards.py               # Phase 3 候选函数代码级护栏：导出置顶 + 库函数排除 + Top N 补足
├── state.py                          # AnalysisState(TypedDict) + Pydantic 输出模型
│                                     #   (StringAnalysis / ApiBehaviorAnalysis / ExportInterfaceAnalysis
│                                     #    / BehaviorProfile / FunctionBoundaryAnalysis / SchedulerDecision
│                                     #    / VerificationReport / AnalysisTask / TaskManifest / TopicAnalysis 等)
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
│   ├── docs_tools.py                 # docs 归档层（AGENT_XX 五要素 Markdown）+ USER.md 异步沟通读写
│   └── token_stats.py                # Token 统计（StageTokenStats / AnalysisTokenReport）
├── workers/                          # Worker 定义
│   ├── specs.py                      # WorkerSpec frozen dataclass + 7 个 spec（5 worker + scheduler + verification）
│   ├── shared_prompts.py             # 五段式提示词模板
│   ├── extractor.py                  # 摘要提取 prompt 构建（build_extraction_prompt，节点内单次 llm.ainvoke 调用）
│   ├── knowledge/                    # 专项分析方法论知识库（arch_detection 路由 + load_arch_guide 工具；
│   │                                 #   C1 起 9 份：windows_pe 基线 + file_loader_triage + cpp/golang/rust
│   │                                 #   + vm_protected/lua_scripted_agent/encrypted_database/yara_embedded）
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
│   │   ├── function_deep_analyzer.py # Phase 3 函数级深度分析 prompt 构建
│   │   └── verification_agent.py     # Phase 3 后置验证 Worker 提示词（high 发现证据回查）
│   ├── topics/
│   │   └── topic_prompts.py          # Phase 3 主题轨 prompt 构建（五段式 + 8 主题方法论要点）
│   └── phase4/
│       ├── synthesis_agent.py        # Phase 4 分片综合 / 聚合 prompt
│       └── report_generator.py       # Phase 4 综合报告 Worker prompt（Markdown 手册）
├── webui/                            # Web UI 审查面板（路线图 P3 项，2026-10-09 落地）
│   ├── server.py                     # FastAPI 后端：启动分析/状态/审批负载/人工决定/报告 + 静态托管
│   └── static/index.html             # 单页面前端（无构建链，marked.js CDN 渲染报告，回退纯文本）
├── docs/
│   ├── RevAgent_LangGraph迁移方案.md  # ADK → LangGraph 迁移方案
│   └── architecture/                 # 架构图示（HTML/PNG，历史产物）
├── data/
│   ├── input/                        # 输入：放置 *_export_for_ai 的 IDA 导出目录（自动发现）
│   │   └── module.upx_export_for_ai/ # 示例 fixture
│   └── output/                       # 输出（黑板）：{project_name}/{extracts,artifacts,summary,meta}
│                                     #   + docs/{project_name}/{AGENT_XX_*.md,USER.md}（归档层）
└── tests/                            # 测试（编排层通过假模型注入 + graph.ainvoke 离线运行）
```

---

## 7. 扩展路线图

### P1 — 高优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **技能知识精修** ✅ 已落地 | 将 `arch_windows_pe.md` 中的专项分析知识（DLL插件型/文件加载型/API哈希动态解析等）精修进各 Worker 提示词（2026-10-09：五段式结构与 output_schema 不变，仅角色/输入/维度三段文本精修；`tests/test_workers.py` 新增 5 条概念性关键词断言锁定知识点） | `workers/phase0/*.py`, `workers/phase1/*.py` |
| **函数级深度分析** ✅ 已落地 | 对候选函数进行逐函数汇编级分析 | `graph_nodes.make_phase3_function_node`（Send 并行扇出） |
| **Worker output_schema 化** ✅ 已落地 | WorkerSpec 声明 `output_schema`（Pydantic），根治 JSON 字符串状态；2026-10-09 起 6 个 spec 全覆盖 | `workers/specs.py`、`state.py`（`StringAnalysis` / `ApiBehaviorAnalysis` / `ExportInterfaceAnalysis` / `BehaviorProfile` / `FunctionBoundaryAnalysis` / `SchedulerDecision`） |
| **Phase 3 并行扇出** ✅ 已落地 | 用 LangGraph `Send` 将逐函数分析扇出为真并行（并发上限 `analysis.phase3_max_concurrency`） | `graph.py` + `graph_nodes.py`（Step 3，2026-10-09） |
| **SqliteSaver + interrupt()** ✅ 已落地 | checkpointer 持久化图状态，HITL 用 `interrupt()` 恢复而非 CLI 阻塞 | `graph_nodes.py`（approval_gate）、`main.py`（AsyncSqliteSaver + 中断循环） |
| **候选函数护栏** ✅ 已落地（A0） | 导出函数强制置顶 + 高 xref 尾部无名库函数排除，根治"Top 20 全是 CRT 库函数"（2026-10-10） | `candidate_guards.py` + `graph_nodes._select_phase3_candidates` + `workers/phase1/function_boundary_detector.py`（提示词同向修正） |
| **任务清单数据模型** ✅ 已落地（A1） | `AnalysisTask` / `TaskManifest` 模型 + scheduler `proposed_topics` 字段（主题词表见 `state.ANALYSIS_TOPIC_VOCABULARY`）（2026-10-10） | `state.py`、`workers/phase2/scheduler.py` |
| **主题制 Phase 3 双轨编排** ✅ 已落地（A2） | 主题 Worker（`workers/topics/`，五段式 + 8 主题方法论）+ `TaskManifest` 落地（主题归组/函数兜底/依赖分波）+ 双轨图拓扑（phase3_topic / phase3_function / phase3_wave2 / phase3_topic_dep）+ MODIFY 圈外地址无条件采纳修复（2026-10-10） | `graph_nodes.py`、`graph.py`、`workers/topics/topic_prompts.py`、`state.py`（`TopicAnalysis`） |

### P2 — 中优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **验证 Worker** ✅ 已落地 | 对 high 置信度发现自动触发验证，检测幻觉和过度推断（2026-10-09：`phase3_function → verification_agent → shard_synthesis`，verified/disputed/unverifiable 三分类 → `verification_report`） | `workers/phase3/verification_agent.py` + `workers/specs.py`（spec）+ `state.py`（`VerificationReport`） |
| **ALL_IN_ONE 生成 Worker** ✅ 已落地 | 整合所有分析结论，生成面向动态调试的综合参考手册（2026-10-09：`aggregator → report_generator → END`，Markdown 落盘 `data/output/{project}/final_report.md` + `artifacts/p4_final_report_meta.json` 元数据；2026-10-10 9 章化：对齐金标准 ALL_IN_ONE 骨架 + 主题摘要接入 Phase 4 三节点 + `topic_conclusions` 进 p4_final_report + USER.md focus/exclude 注入） | `workers/phase4/report_generator.py` + `graph_nodes.make_report_generator_node` |
| **归档输出** ✅ 已落地（A3） | Worker 输出按 `docs/{项目名}/AGENT_XX_{主题}.md` 规范落盘（2026-10-10：`tools/docs_tools.py` 五要素渲染 + `orchestrator_node` 在 Phase 3 后统一归档；USER.md 异步沟通通道同步落地，Web UI 增"沟通记录"页签与 usermd 端点） | `tools/docs_tools.py` + `graph_nodes.orchestrator_node` + `webui/` |
| **模型分层 + token 预算闸门** ✅ 已落地（B1） | 轻任务（Phase 0 triage / scheduler / verification / extractor）可配置小模型（`llm.light_*`，缺省回退主模型零行为变化，`WorkerSpec.tier` + `get_llm(tier)` 双单例）；`analysis.token_budget` 总预算闸门：超限 `interrupt(kind=token_budget)` 挂起，resume 步进放行（2026-10-10） | `graph_nodes.py` + `workers/specs.py` + `observability.py`（注册表）+ `webui/`（decision 透传 + 前端"继续"按钮） |
| **预提取加码 + 函数分桶 + 反编译 fallback 路由** ✅ 已落地（B2） | Phase -1 新增零 token 确定性产物：`strings_categorized.json`（8 类字符串分类）/ `imports_categorized.json`（API 功能分类）/ `functions_buckets.json`（护栏同款四桶分桶）；`load_strings` / `load_imports` / `load_function_index` 传 `project_name` 时优先读产物；`load_function_data` 显式标注 `decompile_failed`，函数/主题 prompt 检测后切换反汇编专项段（2026-10-10） | `tools/file_loaders.py` + `tools/blackboard_tools.py` + `workers/phase3/function_deep_analyzer.py` + `workers/topics/topic_prompts.py` |
| **知识库扩容（框架/引擎指南）** ✅ 已落地（C1） | `workers/knowledge/` 新增 4 份提炼改写指南（vm_protected / lua_scripted_agent / encrypted_database / yara_embedded，每份 ≤1200 tokens）；`ArchDetection` 新增可选 `code_frameworks` 多值字段（词表 `ARCH_CODE_FRAMEWORK_VOCABULARY`），`match_guides` 支持列表字段成员匹配，string_artifact_analyst 的 arch_detection 维度内含框架字符串特征速查（2026-10-10） | `workers/knowledge/*.md` + `workers/knowledge/base.py` + `state.py` + `workers/phase0/string_artifact_analyst.py` |
| **focus/exclude 用户分析优先级** ✅ 已落地（C2） | CLI `--focus`/`--exclude` + config.yaml `analysis.focus`/`exclude` + Web UI start 请求体 → state `user_focus`/`user_exclude` → pre_extract 幂等落盘 USER.md → Worker/主题/函数/报告四类节点统一注入（两来源合并去重）；exclude 约束对齐金标准：不阻塞、标注"用户指示不深入分析此部分"、只给动调提取方案（2026-10-10） | `main.py` + `webui/server.py` + `state.py` + `tools/docs_tools.py`（`user_md_set_focus`）+ `graph_nodes.py`（`build_user_priority_text` / `_load_user_special_requirements` / `_sync_user_priority_to_user_md` / `_task_base_payload` 透传）+ `workers/phase3/function_deep_analyzer.py` |
| **LNK 可选子 Agent** | 当检测到 LNK 样本时，动态加载 LNK Metadata Analyzer | 新增 `workers/optional/lnk_analyzer.py` + `detect_sample_type` |

### P3 — 低优先级

| 扩展项 | 说明 | 预计改动 |
|-------|------|---------|
| **多样本关联分析** | 支持同源样本对比（Loader→Downloader→Payload 攻击链） | 新增 `workers/multi_sample/comparison_agent.py` |
| **Web UI 审查界面** ✅ 已落地 | 将审批门渲染为可视化审查面板（配合 interrupt + checkpointer）（2026-10-09：FastAPI 后端 `webui/server.py` + 纯静态单页面 `webui/static/index.html`；复用 main.py 抽出的 `make_saver_cm` / `collect_pending_interrupts` / `resolve_sample_export_dir`，每次推进新开 saver 连接，服务重启后凭 checkpoints.db 恢复审批） | `webui/`（无需独立前端项目） |
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
    "langgraph-checkpoint-sqlite>=3.0",
    "langchain>=1.0",
    "langchain-openai>=1.0",
    "pydantic>=2.0",
    "python-dotenv>=1.0",
    "pyyaml>=6.0",
    "fastapi>=0.115",   # Web UI 审查面板后端
    "uvicorn>=0.30",
]
# [project.optional-dependencies] dev = ["httpx>=0.27"]（FastAPI TestClient 需要）
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
    # --focus "驻留,持久化"     # --focus：可选（C2），用户重点关注领域，优先详写
    # --exclude "加解密过程"    # --exclude：可选（C2），用户排除领域，只保留动调提取方案
```

配置优先级：**CLI 参数 > `config.yaml` > 环境变量 > 默认值**（focus/exclude 对应 `analysis.focus` / `analysis.exclude`，env `FOCUS` / `EXCLUDE`）。输入目录解析规则：显式 `-i` > project-name 前缀匹配 > 唯一候选自动选用；多个候选且无法确定时报错并列出候选。`config.yaml` 配好 `analysis.project_name` 后可无参运行。样本类型永远 auto，由 `pre_extract` 节点调用 `detect_sample_type` 判定。

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

### 9.3 Web UI 审查面板

```bash
python -m webui.server     # 从项目根目录启动；默认监听 127.0.0.1:8300
                           # 地址/端口取 config.yaml 的 webui.host / webui.port
                           #（环境变量 WEBUI_HOST / WEBUI_PORT 兜底）
```

浏览器打开 `http://127.0.0.1:8300/`：输入项目名启动分析 → 面板轮询状态 → 到达审批门时展示定型结论、高风险指标计数与 Top 20 候选函数表格 → CONFIRM 放行或勾选函数地址后 MODIFY 提交 → 完成后渲染 `final_report.md`。人工协作面板分"人工审批 / 沟通记录"两个页签：沟通记录页签实时展示 `docs/{project}/USER.md` 中的 Agent 提问，逐条回复提交后只落盘（不影响图运行，Agent 在下一波主题分析前读取）。图状态仍在 `data/output/{project}/checkpoints.db`（thread_id = 项目名），服务重启后输入同一项目名点"查询/接管现有项目"即可恢复审批现场。接口：`POST /api/analysis/start`（请求体 `project_name` / `input_name` / `resume` / **C2：`focus` / `exclude`**，缺省回退 config.yaml 的 `analysis.focus` / `analysis.exclude`）、`GET /api/analysis/{project}/status|review|report|usermd`、`POST /api/analysis/{project}/decision`（`{"decision": "CONFIRM"}` 或 `{"decision": "MODIFY", "functions": [...]}`）、`POST /api/analysis/{project}/usermd/reply`（`{"question_no": n, "answer": "..."}`）。

### 9.4 环境要求

- Python 3.10+
- 根目录 `config.yaml`（模型/路径/分析默认值，随仓库提交）
- `.env` 中的 `API_KEY`（唯一必需的机密配置；`BASE_URL` / `MODEL` 等已迁移至 `config.yaml`，环境变量仅作兜底）
- IDA 无 MCP 导出目录（strings.txt, exports.txt, imports.txt, function_index.txt）
