"""Phase 3 函数级深度分析 prompt 构建。

fallback 路由（B2）：func_data 带 decompile_failed=True（反编译失败，仅反汇编可用）
时，prompt 追加"反编译失败函数专项分析要求"段，切换为反汇编导向的分析重点
（API 调用序列 / 常量魔数 / 缓冲区写入 / 循环语义 / 动调断点建议），
要点取自 workers/knowledge/windows_pe.md 与 file_loader_triage.md 的既有方法论。
"""

FUNC_ANALYSIS_PROMPT_TEMPLATE = """你是一个恶意样本函数级分析专家。

当前分析函数：{func_name} ({func_addr})
函数大小：{size} bytes

【数据充足性检查 —— 强约束】
如果同时满足以下任一条件：
- 反编译代码片段为空或仅包含 "(无反编译数据)"
- 反汇编代码片段为空或仅包含 "(无反汇编数据)"
- 反编译 + 反汇编总行数 < 5 行
→ 立即返回 {{"status": "insufficient_data", "reason": "代码片段不足，无法分析", "func_addr": "{func_addr}", "func_name": "{func_name}"}}
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
3. 可疑行为标记
4. 与其他已分析函数的关联
5. 置信度

输出格式（严格 JSON，最多2层嵌套，≤ 1000 tokens）：
{{
  "func_addr": "{func_addr}",
  "func_name": "{func_name}",
  "status": "success|insufficient_data",
  "functionality": "...",
  "key_apis": [...],
  "suspicious_behaviors": [...],
  "related_functions": [...],
  "confidence": "high|medium|low",
  "analysis_notes": "..."
}}

约束：
- confidence=high → 必须有明确的 API 调用链证据（≥2 个具体 API 名称出现在代码片段中）
- suspicious_behaviors 中每项必须有具体的代码片段引用
- 如果数据不足，只输出 status=insufficient_data 的最小 JSON
"""

# 反编译失败函数（fallback）专项提示词段（B2）。
# 要点取自 workers/knowledge/windows_pe.md 与 file_loader_triage.md 的既有方法论：
# 哈希循环特征（ror/rol 0x0D）、解密算法静态识别（XOR/RC4/AES 常量）、
# 载荷处理三关键地址（读取点/解密完成点/执行点）、静态验证清单（缓冲区写入后 MZ 比较）。
DISASM_FALLBACK_SECTION = """

## 反编译失败函数专项分析要求（本函数反编译失败，只有反汇编可用）
该函数反编译失败（常见原因：函数过大、控制流平坦化、算术混淆），输入中只有反汇编片段。
请切换为反汇编导向的分析路径，遵循以下要点：
1. 不要求逐指令还原算法——以指令块级语义为单位归纳行为
2. API 调用序列优先：逐个列出 call 指令的目标（导入表条目/内部子函数），调用序列即行为骨架；出现 ror/rol 0x0D 或固定 XOR 常量的紧凑循环紧跟 call reg 时，按 API 哈希动态解析判定
3. 常量与魔数：留意 XOR/ADD 密钥常量、RC4 的 S 盒初始化双重循环（256 次交换）、AES 的 S 盒常量表（0x63, 0x7c, 0x77...）、跳转表比较常量（cmp reg, 小整数后 jmp [reg*8+table] 是命令分发的特征）
4. 字符串与缓冲区写入地址：追踪写入全局/栈缓冲区的立即数与字符串引用目标地址；缓冲区写入后紧跟 MZ（4D 5A）/PE 头比较是载荷解密完成点的强信号
5. 循环结构语义：识别解码循环（逐字节异或/加减）、拷贝循环、哈希循环的边界条件与步长，给出循环级语义而非逐条指令
6. 动态调试验证建议：给出值得下断点的具体地址（API 调用点、解码循环出口、缓冲区写完成点——即读取点/解密完成点/执行点三段）
输出 JSON 格式与置信度规则不变；key_apis 以 call 指令目标为准，evidence 引用反汇编行。"""


def build_func_analysis_prompt(
    func_addr: str,
    func_name: str,
    func_data: dict,
    guides: str = "",
    project_name: str = "",
    special_requirements: str = "",
) -> str:
    """为单个函数构建分析 prompt。

    当提供 guides 时，会追加当前生效的知识方法论，使分析器能够遵循架构相关的分析规则；
    当提供 project_name 时，也会追加进去，使分析器可以将其传给 load_arch_guide 工具。
    func_data 带 decompile_failed=True 时追加反汇编专项分析段（B2 fallback 路由）。
    special_requirements（C2）：用户分析重点与排除约束（启动参数 + USER.md 合并文本），
    追加在方法论之后，作为最高优先级的分析范围约束。
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

    # 反编译失败 fallback：切换到反汇编专项分析要求（正常函数路径不变）
    if func_data.get("decompile_failed"):
        prompt += DISASM_FALLBACK_SECTION

    # 依据样本架构自动注入的专项分析方法论，优先于通用分析要求遵循
    if guides:
        prompt += (
            "\n\n## 专项分析方法论（依据样本架构自动注入，优先遵循）\n"
            + guides
        )
    # C2 用户分析重点与排除约束：最高优先级的分析范围约束
    if special_requirements:
        prompt += (
            "\n\n## 用户分析重点与排除约束（最高优先级，严格遵守）\n"
            + special_requirements
        )
    if project_name:
        prompt += (
            f"\n\n当前黑板项目名：{project_name}"
            "（如需调用 load_arch_guide 工具，project_name 参数填此值。）"
        )
    return prompt
