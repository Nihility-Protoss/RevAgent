FIVE_SECTION_TEMPLATE = """
【角色定义】
{role_definition}

【输入数据】
{input_data_description}

【分析维度】
{analysis_dimensions}

【输出格式】
{output_format}

【误差控制】
{error_control}
"""

# 统一 WorkerOutput JSON 外壳：所有 Worker 的结构化输出都必须套用这个外壳，
# 由框架层 bb_write_worker_output 投影为版本化条目。
WORKER_OUTPUT_SHELL = """{
  "status": "success",
  "conclusion": "不超过 500 字符的简短结论",
  "confidence": "high",
  "payload": {},
  "evidence_refs": ["functions_extract:0x401000"],
  "annotations": {}
}"""

JSON_OUTPUT_RULE = """
你必须输出严格格式的JSON，不要任何额外文本或markdown标记。输出必须是统一的 WorkerOutput 外壳：

__SHELL__

规则:
1. 所有输出JSON的第一层必须恰好包含外壳字段: status / conclusion / confidence / payload / evidence_refs / annotations
2. status 取值: "success" | "insufficient_data" | "parse_failed"
3. status=success 时，payload 必须按本 Worker 的 payload 形状填写（见下）
4. insufficient_data 和 parse_failed 也必须使用完整外壳：conclusion 写具体原因、confidence=low、payload 为空对象，不得省略其他字段
5. severity为high的判断必须有明确且强烈的证据支持，evidence_refs 引用输入数据中的具体位置
6. 所有判断必须基于输入数据中存在的字段值
7. 字段值为null或缺失时，输出null而非猜测
8. payload 嵌套层级不得超过2层（顶层+1层子对象/数组）

本 Worker 的 payload 形状（填入外壳的 payload 字段）：
__JSON_SCHEMA__
""".replace("__SHELL__", WORKER_OUTPUT_SHELL)

CONFIDENCE_RULES = """
置信度评估标准：
- high: 基于明确、无歧义的字段值做出的判断，且 evidence_refs 中给出逐字引用的原始数据位置
- medium: 基于经验规则但需要上下文确认的判断，evidence_refs 非空
- low: 基于微弱信号或多种解释可能

绝对禁止:
- 猜测字段值（如果数据缺失，明确标注insufficient_data）
- 引用不存在的API或功能
- 做出超出给定数据支持范围的推断
- 基于"常见恶意软件行为模式"补全缺失环节
"""

DATA_SUFFICIENCY_RULE = """
【第一步：数据充足性检查】
在输出任何分析结论前，先判断输入数据是否足以支撑分析：
- 如果输入数据为空、仅包含占位符、或关键字段全部缺失 → 只输出完整外壳且 status="insufficient_data"，conclusion 写明具体原因、confidence="low"、payload 为空对象
- 如果数据存在但条目数量过少（如 strings < 10 条、imports < 5 个 API、functions < 5 个） → status 可为 success 但 confidence 不得高于 low，且 payload 中的推断在 annotations 标注 "weak_evidence"
- 只有在数据质量足够时才进入完整分析流程
"""
