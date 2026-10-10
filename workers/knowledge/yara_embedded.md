---
name: yara_embedded
title: 内嵌 YARA 引擎样本静态分析方法论
source: 提炼改写自本地参考包 code-frameworks/arch_yara_embedded.md (v1.0)
applies_to: [code_frameworks:yara_embedded]
priority: 100
max_tokens: 1200
---

# 内嵌 YARA 引擎样本静态分析方法论

## 适用条件
arch_detection.code_frameworks 含 yara_embedded 的样本（二进制内嵌 libyara：安全 Agent、
扫描器、查杀工具或带检测能力的恶意软件）。

## 识别特征（arch_detection 证据）
- `yr_compiler_create`、`yr_rules_scan_mem`、`yr_scanner_create`、`libyara` 字符串/符号 → high。
- 明文规则片段（`rule xxx { strings: ... condition: ... }`）出现在字符串表 → high。
- 编译后规则魔数（.yarc 的 YARA 头）、大段高熵规则数据块 → 辅助证据。

## 核心函数链定位（重命名优先级顺序）
1. 规则编译入口：`yr_compiler_add_string` / `add_file` / `add_fd`。
2. 规则加载入口：`yr_rules_load` / `yr_rules_load_stream`。
3. 扫描执行：`yr_rules_scan_file` / `scan_proc` / `scan_mem`、`yr_scanner_scan_mem`。
4. 扫描器管理：`yr_scanner_create` / `yr_scanner_set_timeout` / `destroy`。
5. 结果处理：扫描回调与结果上报函数。

## 规则来源五分（提取方法各不同）
- 硬编码 .yarc：.rdata/资源节内嵌，直接 dump 后用 yara 工具加载验证（编译后格式不可逆，要明文须找原始来源）。
- 数据库加密：SQLite 字段 Base64+AES 封装（见 encrypted_database 指南），解密后还原 .yar。
- JSON+Base64 封装：解析 JSON 取 content 字段解码即得明文规则。
- Lua 层动态传入：`yara.compile(rule_text)` 类调用点下断，抓运行时规则文本。
- 远程下发：追 HTTP 响应解析函数，抓增量更新的规则包。

## 触发条件与扫描目标
- 触发方式：定时（周期与范围）、事件驱动（ETW/回调/钩子/ReadDirectoryChangesW）、手动任务下发、文件变更监控、进程事件（创建/加载 DLL）。
- 扫描目标：`scan_file`（路径范围、递归深度、大小过滤）；`scan_proc`（目标 PID 选择、内存区域、常伴 OpenProcess+ReadProcessMemory）；`scan_mem`（缓冲区大小与超时控制）。
- 结果去向：上报 / 隔离 / 告警的处理链单独还原。

## 断点策略
- `yr_compiler_add_string` 入口：直接捕获明文规则全文（最高价值断点）。
- `yr_rules_scan_*` 入口：确认扫描目标与所用规则集。
- Lua 边界 compile 调用点：抓 Lua 层传入的规则文本。
- 扫描结果回调：观察命中后的处理流程。

## 置信度规则
- high：libyara 符号 + 规则片段/魔数 + 扫描调用链齐备。
- medium：仅 `yr_` 前缀符号或 libyara 字符串。
- low：仅明文规则样式片段，需函数级证据佐证。
