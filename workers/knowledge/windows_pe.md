---
name: windows_pe
title: Windows PE 样本静态分析方法论
source: docs/MalwareAnalysis/malware-analysis/arch_windows_pe.md (v1.1)
applies_to: [baseline]
priority: 10
max_tokens: 1200
---

# Windows PE 样本静态分析方法论

## 适用条件
所有 Windows PE 样本的默认基线方法论，与其他专项指南叠加使用。

## 快速定性（API + 字符串双视角）
- **strings.txt 优先级高于 imports.txt**：加壳/混淆样本的导入表可能只剩 LoadLibrary/GetProcAddress，真实行为意图藏在字符串里；字符串为空或全乱码时才以导入表为主。
- 字符串定性顺序：路径与文件名（`C:\`、`AppData`、`Temp`）→ 注册表键（`Software\Microsoft\Windows\CurrentVersion\Run`）→ URL/IP/域名 → 命令行片段（`cmd /c`、`powershell`、`-enc`）→ 互斥体/服务名。
- 导入定型顺序：进程注入三件套（OpenProcess/WriteProcessMemory/CreateRemoteThread 或 RtlCreateUserThread）→ 持久化（RegSetValueEx + 服务 API）→ 反调试（IsDebuggerPresent、CheckRemoteDebuggerPresent、NtQueryInformationProcess）→ 网络（WinHTTP/WinInet/socket）。

## API 哈希动态解析识别
导入表缺失但函数密集时，按以下静态特征判定动态解析：
- 访问 PEB：`gs:[0x60]`（64 位）/`fs:[0x30]`（32 位）定位 LDR，遍历模块链表。
- 哈希循环：`ror/rol 0x0D` 或固定 XOR 常量的紧凑循环，紧跟 `call rax`/`call reg` 间接调用。
- 系统调用直调：导入表为空但存在 `mov eax, <syscall号>; syscall/sysenter` 序列。
出现以上特征时，报告"API 哈希动态解析，置信度 high"，行为定性必须回落到字符串证据。

## 文件加载型核心逻辑定位（纯静态近似）
无法使用 xrefs_to 时，用函数索引 + 字符串证据近似：
1. 在 strings 中定位 shellcode/载荷文件名、MZ 头魔数、`This program cannot be run in DOS mode`。
2. 在 function_index 中筛选引用这些字符串所在地址的函数（IDA 导出含 xrefs 时直接用）。
3. 候选函数按"五段式行为链条"核对（见 file_loader_triage 指南）。
DLL 插件型样本（导出表含 Install/Start/ServiceMain 类导出）优先分析导出函数本体。

## 命令分发与配置解析
- 命令分发结构：比较指令常量后立即跳转表（`cmp reg, 0x06; ja default; jmp [reg*8+table]`），常量值即 cmd_id，逐个还原语义。
- 配置解析：全局缓冲区 + 逐字段读写，注意 XOR/ADD 常量的解码循环；配置字段顺序常与 C2 协议字段一致。

## 敏感行为模式速查
- 浏览器窃取：访问 `Login Data`、`Cookies`、`Web Data`（Chromium）或 `logins.json`（Firefox），配合 `CryptUnprotectData`。
- 持久化：Run 键、计划任务（`schtasks` 字符串）、服务创建（`CreateService`）、WMI 事件订阅。
- 注入：进程名白名单（`explorer.exe`、`svchost.exe`）+ 打开进程 + 写内存 + 远线程。

## 置信度规则
- high：上述特征在反编译片段或字符串中有明确、无歧义的证据。
- medium：仅有字符串或仅有 API 之一支撑。
- low：基于家族先验的推断，必须注明推断依据。
