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

JSON_OUTPUT_RULE = """
你必须输出严格格式的JSON，不要任何额外文本或markdown标记：
{json_schema}

规则:
1. 所有输出JSON的第一层必须包含字段: "status": "success|insufficient_data|parse_failed"
2. 如果输入数据为空、仅包含占位符、或关键字段全部缺失 → 只输出 {{"status": "insufficient_data", "reason": "具体原因"}}，不输出其他字段
3. 如果数据存在但质量低 → "status" 为 "success" 但所有 confidence 不得高于 low，且推断标注 "weak_evidence"
4. 如果无法按schema输出 → 允许输出 {{"status": "parse_failed", "raw_thoughts": "分析思路"}}
5. severity为high的判断必须有明确且强烈的证据支持
6. 所有判断必须基于输入数据中存在的字段值
7. 字段值为null或缺失时，输出null而非猜测
8. JSON嵌套层级不得超过2层（顶层+1层子对象/数组）
"""

CONFIDENCE_RULES = """
置信度评估标准：
- high: 基于明确、无歧义的字段值做出的判断，且必须在 evidence.raw_value 中逐字引用原始数据
- medium: 基于经验规则但需要上下文确认的判断，evidence.raw_value 非空
- low: 基于微弱信号或多种解释可能

证据链要求（所有 high/medium 判断必须附带）：
- evidence.raw_value: 输入数据中存在的原始值，逐字引用
- evidence.location: 该值在输入中的位置/字段名
- evidence.inference_chain: 从 raw_value 到 judgment 的推导步骤（最多2步，禁止跳跃推断）

绝对禁止:
- 猜测字段值（如果数据缺失，明确标注insufficient_data）
- 引用不存在的API或功能
- 做出超出给定数据支持范围的推断
- 基于"常见恶意软件行为模式"补全缺失环节
"""

DATA_SUFFICIENCY_RULE = """
【第一步：数据充足性检查】
在输出任何分析结论前，先判断输入数据是否足以支撑分析：
- 如果输入数据为空、仅包含占位符、或关键字段全部缺失 → 只输出 {"status": "insufficient_data", "reason": "输入数据缺失或为空"}，不输出其他字段
- 如果数据存在但条目数量过少（如 strings < 10 条、imports < 5 个 API、functions < 5 个） → status 可为 success 但 confidence 不得高于 low，且所有推断必须标注 "weak_evidence"
- 只有在数据质量足够时才进入完整分析流程
"""
