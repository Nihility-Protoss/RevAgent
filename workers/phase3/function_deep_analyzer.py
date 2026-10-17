FUNC_ANALYSIS_PROMPT_TEMPLATE = """你是一个恶意样本函数级分析专家。

当前分析函数：{func_name} ({func_addr})
函数大小：{size} bytes

【数据充足性检查 —— 强约束】
如果同时满足以下任一条件：
- 反编译代码片段为空或仅包含 "(无反编译数据)"
- 反汇编代码片段为空或仅包含 "(无反汇编数据)"
- 反编译 + 反汇编总行数 < 5 行
→ 立即返回 {{"status": "insufficient_data", "conclusion": "代码片段不足，无法分析", "confidence": "low", "payload": {{}}, "evidence_refs": [], "annotations": {{}}}}
禁止在代码片段不足时进行任何功能推断。

输入数据：
- 反编译代码片段（截断到前 {max_lines} 行）:
{decompile_snippet}

- 反汇编代码片段（截断到前 {max_lines} 行）:
{disassembly_snippet}

- 调用关系（xrefs）：
入向: {xrefs_in}
出向: {xrefs_out}

分析要求：
1. 函数功能判定（初始化/网络/加密/反调试/文件操作/注册表/...）
2. 关键 API 调用链
3. 可疑行为标记（每项必须引用具体代码片段作为证据）
4. 与其他已分析函数的关联
5. 置信度（high 必须有明确的 API 调用链证据，≥2 个具体 API 名称出现在代码片段中）

输出格式（严格 JSON，最多2层嵌套，≤ 1000 tokens）：
{{
  "status": "success",
  "conclusion": "本函数功能的一句话结论",
  "confidence": "high|medium|low",
  "payload": {{
    "functionality": "函数功能描述",
    "key_apis": ["API1", "API2"],
    "suspicious_behaviors": [{{"behavior": "...", "evidence": "代码片段引用"}}],
    "related_functions": ["0x402000", ...],
    "analysis_notes": "分析备注与不确定性"
  }},
  "evidence_refs": ["证据引用，如 decompile:0x401000"],
  "annotations": {{"recommended_name": "有意义的 snake_case 函数命名"}}
}}

约束：
- annotations.recommended_name 仅在能确定函数用途时给出，使用有意义的 snake_case；
  没有把握时省略该键，禁止猜测命名。
- suspicious_behaviors 中每项必须有具体的代码片段引用。
- 如果数据不足，只输出 status=insufficient_data 的最小 JSON。
"""


def build_func_analysis_prompt(
    func_addr: str,
    func_name: str,
    func_data: dict,
    guides: str = "",
) -> str:
    """为单个函数构建分析 prompt。

    当提供 guides 时，会追加当前生效的知识方法论，使分析器能够遵循架构相关的分析规则。
    """
    decompile = func_data.get("decompile_snippet") or "(无反编译数据)"
    disasm = func_data.get("disassembly_snippet") or "(无反汇编数据)"
    xrefs_in = func_data.get("xrefs_in", [])
    xrefs_out = func_data.get("xrefs_out", [])

    prompt = FUNC_ANALYSIS_PROMPT_TEMPLATE.format(
        func_addr=func_addr,
        func_name=func_name,
        size=func_data.get("size", 0),
        max_lines=120,  # 从 200 下调
        decompile_snippet=decompile[:2500] if len(decompile) > 2500 else decompile,  # 从 4000 下调
        disassembly_snippet=disasm[:2500] if len(disasm) > 2500 else disasm,  # 从 4000 下调
        xrefs_in=xrefs_in or ["无"],
        xrefs_out=xrefs_out or ["无"],
    )

    # 依据样本架构自动注入的专项分析方法论，优先于通用分析要求遵循
    if guides:
        prompt += (
            "\n\n## 专项分析方法论（依据样本架构自动注入，优先遵循）\n"
            + guides
        )
    return prompt
