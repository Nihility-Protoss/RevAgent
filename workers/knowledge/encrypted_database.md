---
name: encrypted_database
title: 嵌入式加密数据库样本静态分析方法论
source: 提炼改写自本地参考包 code-frameworks/arch_encrypted_database.md (v1.0)
applies_to: [code_frameworks:encrypted_sqlite]
priority: 100
max_tokens: 1200
---

# 嵌入式加密数据库样本静态分析方法论

## 适用条件
arch_detection.code_frameworks 含 encrypted_sqlite：样本把脚本、规则、配置、日志加密存入
SQLite 数据库文件（.db/.dat），常与 lua_scripted / yara_embedded 指南叠加使用。

## 识别特征（arch_detection 证据）
- `sqlite3_open`、`sqlite3_prepare_v2`、`sqlite3_step`、`sqlite3_column_blob` 等 API 字符串/导入 → high。
- `.db` / `.dat` 数据文件路径、硬编码路径字符串 → 辅助证据。
- 数据文件头不是 SQLite 魔数 `53 51 4C 69`（"SQLite format 3"）→ 文件级加密强信号。

## 数据来源追踪（路径从何而来）
- 硬编码路径：.rdata 字符串常量，交叉引用到 `sqlite3_open`。
- 运行时拼接：`GetModuleFileName` / `GetTempPath` + 路径拼接函数，追参数来源。
- 资源节释放：`FindResource` → `LoadResource` → `WriteFile` 序列，记资源 ID 与落地路径映射。
- 远程下载：HTTP 响应写入本地文件的数据流。

## 加密层级三分（决定解密切入点）
- **文件级**：整库加密，打开前整体解密 → 在 `sqlite3_open` 之前找解密调用。
- **字段级**：仅 content/data 字段是密文，其余明文 → 追 `sqlite3_column_blob` 返回值是否先过解密函数再给加载器。
- **VFS 流式**：自定义 `sqlite3_vfs`，xRead/xWrite 回调内嵌解密 → 搜 `sqlite3_vfs_register`，分析回调。

## 密钥提取策略
1. 硬编码：.rdata 中 16/24/32 字节高熵字符串。
2. 派生：找 derive_key 类函数，追输入来源（机器 UUID、硬盘序列号等）。
3. 运行时：解密函数入口下断直接读密钥缓冲区（最省事）。
4. 已知明文反推：已知库内应有 `\x1BLua` 字节码头等固定明文时，反推 XOR 密钥。

## 解密后内容识别
按表名与字段推断用途：脚本表（Lua 字节码魔数）、规则表（YARA 语法/JSON 结构）、
配置表（键值对/开关）、日志表（时间戳+事件类型）；注意表间外键依赖（如 scripts 依赖 config 的启用开关）。

## 断点策略
- `sqlite3_open` 入口前：观察传入文件内容是否已解密（判文件级加密）。
- 解密函数出口：dump 明文数据库/字段。
- `sqlite3_prepare_v2`：拿 SQL 原文，推断表结构。
- `sqlite3_column_blob` 返回后：追字段级解密的数据去向。

## 置信度规则
- high：SQLite API 调用链 + 加密层级证据 + 密钥/明文验证齐备。
- medium：仅 SQLite API 证据，加密层级未确认。
- low：仅 .db 路径字符串，需函数级证据佐证。
