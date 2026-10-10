"""主题 Worker 的五段式提示词构建（批次 A2：Phase 3 双轨制之主题轨）。

与逐函数孤立分析（workers/phase3/function_deep_analyzer.py）不同，主题分析围绕
一个分析主题（state.ANALYSIS_TOPIC_VOCABULARY）聚合多个相关函数的上下文，
产出成体系的主题结论（如"30 条命令逐条语义"），对齐金标准 Phase 2 的五要素：
分析对象 / 执行结论 / 关键引用 / 置信度 / 未解之谜。

主题节点不做 ReAct 工具循环（数据由节点内聚后直接注入 prompt，一主题一次主调用），
因此本模块与 function_deep_analyzer 一样采用"模板 + 数据渲染"的构建方式，
但骨架仍沿用 workers/shared_prompts.py 的五段式模板。
"""
import json

from workers.shared_prompts import (
    CONFIDENCE_RULES,
    DATA_SUFFICIENCY_RULE,
    FIVE_SECTION_TEMPLATE,
    JSON_OUTPUT_RULE,
)

# 主题词 → 中文名（prompt 角色段与输出展示用）
TOPIC_TITLES = {
    "init_config_decrypt": "初始化与配置解密",
    "command_dispatcher": "命令分发器",
    "persistence": "驻留持久化",
    "injection_loader": "注入与加载",
    "stealer": "信息窃取",
    "network_stack": "网络通信栈",
    "anti_analysis": "反分析对抗",
    "export_interface": "导出接口",
}

# 每个主题一段方法论要点（分析维度段的核心内容）。
# 要点只描述"该主题下应该回答什么问题、按什么路径排查"，不预设样本结论。
TOPIC_METHODOLOGIES = {
    "init_config_decrypt": """- 定位加密配置区：在反编译片段中找大块字节数组/全局缓冲区引用与 memcpy/循环拷贝
- 识别解密算法：单字节/滚动 XOR 密钥、RC4 的 KSA/PRGA 双循环特征、AES/DES 的常量表与轮结构
- 还原配置字段：解密后的 C2 地址、密钥、版本号、互斥体名、开关标志，逐字段列出偏移与含义
- 初始化顺序：解密发生在 DllMain/导出函数哪个阶段，解密结果写入哪些全局变量供后续模块消费""",
    "command_dispatcher": """- 定位分发点：switch-case 跳转表、if-else 命令比较链、回调函数指针表三种形态
- 逐条还原命令语义：每个 cmd 编号/命令字符串 → handler 地址 → 参数 → 行为结论，禁止只报编号不报语义
- 命令来源：命令从网络收包、导出函数参数还是配置文件读取，偏移量与解码方式
- 覆盖度自查：发现的命令总数、已还原语义的条数、无法还原的条目列入 unresolved""",
    "persistence": """- 驻留方式枚举：注册表 Run 键、服务创建、计划任务、启动目录、WMI 订阅、DLL 劫持/侧加载
- 触发链还原：从安装函数到落地文件/键值的完整写入路径，含自拷贝与伪装命名
- 存活策略：看门狗线程、多机制互备、卸载/自删除条件
- 每条机制给出写入目标（键路径/文件路径/服务名）的逐字证据""",
    "injection_loader": """- 注入链识别：OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread/QueueUserAPC 组合
- 载荷形态：shellcode 直写、反射 DLL 加载（ReflectiveLoader 特征：自解析导出表/重定位）、镂空进程（process hollowing）
- 目标进程选择：硬编码进程名、枚举遍历、傀儡进程创建（CREATE_SUSPENDED）
- 装载后入口：新线程起始地址指向哪里，参数块如何构造""",
    "stealer": """- 窃取目标枚举：浏览器凭据/Cookie/自动填充（Login Data、Cookies、logins.json）、钱包、邮件、FTP、系统信息
- 数据定位路径：%APPDATA% 拼接的具体目录、注册表读取的软件配置
- 采集与打包：SQL 查询（sqlite3）、解密（CryptUnprotectData）、暂存文件与打包格式
- 每条窃取能力给出目标 + 数据路径 + 关键 API 的三元组结论""",
    "network_stack": """- C2 协议还原：HTTP/HTTPS/自定义 TCP/UDP，请求方法、URI 模板、Header 构造
- 报文格式：加密/编码层（AES、RC4、base64、异或）在哪一步施加，密钥来自哪个配置字段
- 会话流程：上线包 → 心跳 → 任务下发 → 结果回传的完整时序
- 依赖配置：C2 地址/端口/密钥等字段若来自配置解密结论，注明引用关系（前置主题 init_config_decrypt）""",
    "anti_analysis": """- 反调试：IsDebuggerPresent、CheckRemoteDebuggerPresent、NtQueryInformationProcess、PEB 标志位直读
- 反虚拟机/反沙箱：CPUID、注册表硬件信息、进程列表比对、睡眠加速检测、鼠标/窗口活动探测
- 反分析后果：检测到环境后的行为分支（退出/虚假执行/延迟触发）
- 混淆与对抗：花指令、字符串加密、API 哈希动态解析在函数级片段中的具体表现""",
    "export_interface": """- 导出函数角色判定：初始化 / 命令分发 / 回调注册 / 数据存取 / 清理卸载，逐导出给结论
- ordinal 与名称映射：序号导出（无名称）的参数推断，调用契约（参数个数、结构体布局）
- 插件接口契约：宿主 → 插件的调用顺序、回调结构体填充、版本协商
- 与其他主题的衔接：导出函数分别调用了哪些内部函数（作为 command_dispatcher 等主题的入口线索）""",
}

# 词表外主题的兜底方法论（防御性：dispatch 已过滤词表外取值，正常不会走到）
_FALLBACK_METHODOLOGY = """- 围绕主题词圈定的问题域，逐函数给出角色判定与行为结论
- 跨函数串联调用关系，还原该主题的完整执行链
- 无法确认的部分列入 unresolved，禁止猜测"""

# 反编译失败函数（fallback）专项提示词段（B2）：主题归组函数中混有反编译失败函数时注入，
# 要点与 function_deep_analyzer.DISASM_FALLBACK_SECTION 同源
# （workers/knowledge/windows_pe.md 与 file_loader_triage.md 的既有方法论）。
_TOPIC_DISASM_FALLBACK_NOTE = """
【反编译失败函数专项要求】下方标记"（反编译失败，只有反汇编）"的函数反编译失败
（函数过大/控制流平坦化/算术混淆常见），输入中只有反汇编片段。对这些函数切换为
反汇编导向分析：API 调用序列优先（逐个列出 call 指令目标，ror/rol 0x0D 紧凑循环紧跟
call reg 判为 API 哈希动态解析）；留意常量与魔数（XOR/ADD 密钥、RC4 S 盒 256 次交换
双重循环、AES S 盒常量 0x63,0x7c,0x77、cmp+跳转表的命令分发特征）；追踪字符串与
缓冲区写入地址（写入后紧跟 MZ/4D 5A 比较是载荷解密完成点强信号）；归纳循环结构语义
（解码/拷贝/哈希循环的边界与步长）；并给出动调断点建议（API 调用点、解码循环出口、
缓冲区写完成点）。不要求逐指令还原算法；evidence 可引用反汇编行。"""

_TOPIC_OUTPUT_SCHEMA = """{
  "status": "success|insufficient_data",
  "topic": "主题词（与输入一致）",
  "summary": "主题总体结论（一段话，跨函数综合，禁止逐函数罗列）",
  "findings": [
    {"subject": "分析对象（命令编号/机制名/函数地址）", "conclusion": "对该对象的结论", "confidence": "high|medium|low"}
  ],
  "evidence": [
    {"address": "0x...", "snippet": "逐字引用的代码片段或字符串原文", "source": "decompile|disassembly|strings|imports"}
  ],
  "confidence": "high|medium|low",
  "unresolved": ["未解之谜：数据不足或需动态验证的问题"]
}"""

_TOPIC_INSTRUCTION = FIVE_SECTION_TEMPLATE.format(
    role_definition=DATA_SUFFICIENCY_RULE + "\n\n" + """你是一名恶意样本主题分析专家，负责对{topic_title}（{topic}）主题做跨函数的综合分析。
与逐函数孤立分析不同：你的输入是该主题归组到的多个函数的反编译/反汇编片段，你必须把这些函数串成体系，
产出主题级结论（例如命令分发器主题必须给出逐条命令语义，而不是逐函数的功能罗列）。
核心原则：结论必须锚定到具体函数地址与逐字引用的代码/字符串证据；跨函数推断必须说明衔接关系。""",

    input_data_description="""节点已为本主题归组 {func_count} 个函数，地址集合：{function_addrs}。
每个函数的输入块包含：地址、名称、反编译片段、反汇编片段（均可能截断）。
若提供了前置主题结论（depends_on 主题已完成的摘要），可在本主题分析中直接引用其结论作为已知事实，
但必须保持引用关系可追溯（在 evidence 或 summary 中注明来源主题）。""",

    analysis_dimensions="""本主题（{topic_title}）的方法论要点：
{methodology}

通用维度（所有主题都必须覆盖）：
1. 主题结论：该机制在样本中是否存在、完整度如何、一句话总体结论
2. 逐条目还原：按主题特性拆成条目（逐命令/逐机制/逐目标），每条给出对象 + 结论 + 置信度
3. 关键引用：每条 high/medium 结论必须有地址 + 逐字代码/字符串片段
4. 未解之谜：静态分析无法确认的部分（需动态调试验证的点）显式列出""",

    output_format=JSON_OUTPUT_RULE.format(json_schema=_TOPIC_OUTPUT_SCHEMA) + """
补充约束：
- findings 是逐条目列表：命令分发器主题逐条命令、窃取主题逐条窃取目标、持久化主题逐条机制，以此类推
- evidence.snippet 必须逐字摘自输入片段，禁止改写或编造
- 嵌套层级不得超过 2 层；整体输出控制在 4000 tokens 以内""",

    error_control=CONFIDENCE_RULES + """
主题级特化约束：
- summary 给出跨函数综合结论，但 confidence 不得高于各 finding 置信度的中位水平
- 输入函数与本主题无关时如实说明（findings 可为空），禁止硬凑主题结论
- 前置主题结论只能引用其明确写出的结论，禁止在此基础上继续外推""",
)


def build_topic_prompt(
    topic: str,
    function_addrs: list,
    func_contexts: list,
    *,
    guides: str = "",
    project_name: str = "",
    prerequisites: dict = None,
    special_requirements: str = "",
) -> str:
    """构建主题分析 prompt（五段式指令 + 聚合函数上下文 + 前置主题结论）。

    Args:
        topic: 主题词（建议取 state.ANALYSIS_TOPIC_VOCABULARY；词表外用兜底方法论）。
        function_addrs: 本主题归组的函数地址列表。
        func_contexts: 与 function_addrs 对齐的 load_function_data 返回字典列表。
        guides: 激活知识指南全文（依据样本架构注入，优先遵循）。
        project_name: 黑板项目名（写入 prompt 供溯源）。
        prerequisites: depends_on 前置主题的摘要 {topic: summary_data}，可为 None。
        special_requirements: USER.md 异步通道读取到的用户已回答问题与重点关注
            内容（每波任务开始前由主题节点拼接注入，优先遵循）。
    """
    instruction = _TOPIC_INSTRUCTION.replace("{topic}", topic).replace(
        "{topic_title}", TOPIC_TITLES.get(topic, topic)
    ).replace("{func_count}", str(len(function_addrs))).replace(
        "{function_addrs}", json.dumps(function_addrs, ensure_ascii=False)
    ).replace("{methodology}", TOPIC_METHODOLOGIES.get(topic, _FALLBACK_METHODOLOGY))

    parts = [instruction]

    # 前置主题结论（depends_on 波次的数据流：第二波主题消费第一波摘要）
    if prerequisites:
        parts.append("\n\n## 前置主题结论（depends_on 已完成主题，可作为已知事实引用）")
        for dep_topic, summary in prerequisites.items():
            parts.append(
                f"### {dep_topic}\n"
                + json.dumps(summary, ensure_ascii=False, indent=2)
            )

    # USER.md 异步沟通通道：用户已回答的问题与重点关注内容，优先遵循
    if special_requirements:
        parts.append(
            "\n\n## 特殊要求（用户经 USER.md 异步沟通提供，优先遵循）\n"
            + special_requirements
        )

    # 聚合函数上下文：每函数一块，片段截断控制总量
    parts.append("\n\n## 本主题归组函数上下文")
    if not func_contexts:
        parts.append("（本主题未归组到任何函数，无代码数据）")
    # B2 fallback 路由：存在反编译失败函数时注入一次专项要求说明
    if any(ctx.get("decompile_failed") for ctx in func_contexts):
        parts.append(_TOPIC_DISASM_FALLBACK_NOTE)
    for ctx in func_contexts:
        addr = ctx.get("addr", "?")
        name = ctx.get("name") or f"sub_{str(addr).replace('0x', '')}"
        decompile = ctx.get("decompile_snippet") or "(无反编译数据)"
        disasm = ctx.get("disassembly_snippet") or "(无反汇编数据)"
        # 反编译失败函数在标题行显式标记（其余函数渲染不变）
        fallback_mark = "（反编译失败，只有反汇编）" if ctx.get("decompile_failed") else ""
        parts.append(
            f"\n===== 函数 {name} ({addr}){fallback_mark} =====\n"
            f"[反编译片段]\n{decompile[:2000]}\n"
            f"[反汇编片段]\n{disasm[:2000]}"
        )

    # 依据样本架构自动注入的专项分析方法论，优先于通用要求遵循
    if guides:
        parts.append("\n\n## 专项分析方法论（依据样本架构自动注入，优先遵循）\n" + guides)
    if project_name:
        parts.append(f"\n\n当前黑板项目名：{project_name}")
    return "".join(parts)
