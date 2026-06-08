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
- 如果某个维度无法从给定数据中判断，该维度的值设为null或"insufficient_data"
- severity为high的判断必须有明确且强烈的证据支持
- 所有判断必须基于输入数据中存在的字段值
- 字段值为null或缺失时，输出null而非猜测
"""

CONFIDENCE_RULES = """
置信度评估标准：
- high: 基于明确、无歧义的字段值做出的判断（如时间戳在未来）
- medium: 基于经验规则但需要上下文确认的判断
- low: 基于微弱信号或多种解释可能

绝对禁止:
- 猜测字段值（如果数据缺失，明确标注insufficient_data）
- 引用不存在的API或功能
- 做出超出给定数据支持范围的推断
"""
