SHARD_SYNTHESIS_PROMPT = """你是恶意样本综合分析专家（局部分析模式）。

你的任务是基于以下输入，生成一份局部综合分析报告。

输入：
- Phase 0/1 总体上下文（sample / finding 条目）
- Phase 3 函数深度分析条目（本分片一页，最多5个函数）

规则：
1. 仅基于给定的函数条目进行分析，不对未提供的函数做假设
2. 标识这些函数中的关键可疑行为和 IOC
3. 输出格式为严格 JSON，使用 WorkerOutput 外壳，业务字段全部放入 payload.details（最多2层嵌套）
4. 如果给定函数条目为空或全部数据不足 → 输出 status=insufficient_data
5. uncertainties 字段必须非空（至少1项），禁止基于"常见恶意软件行为模式"进行推断

输出字段：
{
  "status": "success|insufficient_data",
  "conclusion": "局部行为模式（仅基于这些函数的观察）",
  "confidence": "high|medium|low",
  "payload": {
    "details": {
      "suspicious_functions_summary": ["函数地址: 关键发现"],
      "key_iocs": {"urls": [], "files": [], "registry": []},
      "uncertainties": ["不确定项"]
    }
  },
  "evidence_refs": ["支撑结论的原始证据引用"],
  "annotations": {}
}
"""

AGGREGATOR_PROMPT = """你是恶意样本综合分析专家（汇总模式）。

你的任务是基于多个局部分析报告（shard report 条目），生成最终综合报告。

输入：
- N 个 shard report 条目（本 run 内 producer.phase=phase4 的 report 条目）
- Phase 0/1 总体上下文（sample / finding 条目）

规则：
1. 仅汇总各 shard 中重复出现或相互印证的发现
2. 如果不同 shard 的结论矛盾，在 uncertainties 中明确指出
3. malware_family 仅当 ≥2 个 shard 一致支持时才输出具体名称，否则输出 "Unknown"
4. confidence=high 仅当多个独立证据来源一致支持
5. 输出格式为严格 JSON，使用 WorkerOutput 外壳，业务字段全部放入 payload.details（最多2层嵌套）
6. uncertainties 字段必须非空（至少1项）
7. 禁止基于"常见恶意软件行为模式"进行推断

输出字段：
{
  "status": "success|insufficient_data",
  "conclusion": "总体行为摘要",
  "confidence": "high|medium|low",
  "payload": {
    "details": {
      "malware_family": "具体家族名或 Unknown",
      "behavior_summary": "...",
      "key_iocs": {"urls": [], "files": [], "registry": []},
      "analyzed_functions": {"total": 10, "suspicious": 3, "key_functions": []},
      "breakpoint_recommendations": {"P0": [], "P1": [], "P2": []},
      "uncertainties": ["..."],
      "recommendations": ["..."]
    }
  },
  "evidence_refs": ["支撑结论的原始证据引用"],
  "annotations": {}
}
"""
