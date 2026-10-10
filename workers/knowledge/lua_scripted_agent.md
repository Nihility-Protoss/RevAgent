---
name: lua_scripted_agent
title: Lua 脚本引擎样本静态分析方法论
source: 提炼改写自本地参考包 code-frameworks/arch_lua_scripted_agent.md (v1.0)
applies_to: [code_frameworks:lua_scripted]
priority: 100
max_tokens: 1200
---

# Lua 脚本引擎样本静态分析方法论

## 适用条件
arch_detection.code_frameworks 含 lua_scripted 的样本（Lua 5.1 / LuaJIT 驱动的插件化 Agent 类样本）。
核心格局：**业务逻辑在 Lua 层，执行框架与敏感操作在 C 层**。

## 识别特征（arch_detection 证据）
- 字符串/导入出现 `luaL_newstate`、`luaL_openlibs`、`luaL_loadbuffer`、`lua_pcall`、`lua_pushcfunction` → high。
- `.luac` / `.lua` 文件名、LuaJIT 版本字符串 → 辅助证据。

## 分析路线（四步）
1. **C 层加载链定位**：找 `luaL_newstate`（VM 初始化）→ `luaL_openlibs`（标准库范围）→ `luaL_loadbuffer/loadfile/loadstring`（字节码来源）→ `lua_pcall/lua_call`（执行点）；加载前若有解密/解压函数，标注加密层。
2. **字节码提取**：载体排查顺序——PE 资源节（LUA_SCRIPT/RCDATA）→ 加密 SQLite 数据库（见 encrypted_database 指南）→ 独立文件 → 内存动态生成（只能动调 dump）。魔数校验：Lua 5.1 = `1B 4C 75 61`（`\x1BLua`），LuaJIT 2.0/2.1 = `1B 4C 4A 02/03`。
3. **反编译还原**：unluac（5.1）/ luajit-decomp（LuaJIT）；入口脚本通常是最先被 pcall 的 main/init/core；追踪 `require`/`dofile` 建模块依赖图。
4. **C/Lua 交叉验证**：还原 C 函数注册表（见下），确认事件回调绑定的 C 地址，划清权限边界（策略判断在 Lua 层，Hook/驱动通信在 C 层）。

## C 函数注册表还原（C/Lua 映射）
三种注册模式，逐一建"Lua 全局名 → C 函数地址"映射表：
- 单个注册：`lua_pushcfunction` + `lua_setglobal`（名字是字符串参数）。
- 批量注册：`luaL_register`（模块名 + 函数数组，遍历数组逐条映射）。
- 表注册：`lua_newtable` + `lua_pushcfunction` + `lua_setfield`。
常见功能分类：系统监控（enum_process/read_file）、网络通信（http_post/heartbeat）、规则引擎（yara_scan/hash_file）、策略控制（get_policy/set_config）、驱动交互（ioctl_send）。

## 断点策略
- P0（VM 层）：`luaL_loadbuffer` 入口——拿脚本名、字节码缓冲区与大小（dump 字节码的最佳点）；`lua_pcall` 入口——被调函数与参数栈；`lua_pushcfunction`——实时补齐 C/Lua 映射。
- P1（数据层）：数据库解密函数出口——明文 SQLite 落盘；`sqlite3_open` / `sqlite3_prepare_v2`——库路径与 SQL 原文。
- P2（脚本层）：`require` 调用点——模块加载顺序；策略判断函数——当前配置与判定结果。

## 插件加载链要点
记录加载顺序与条件（按配置/环境选脚本）、热更新触发条件、脚本间全局隔离与沙箱边界；
守护线程（异常监控/自动重载）单独标注。

## 置信度规则
- high：C API 调用链 + 字节码魔数 + 注册表映射三类证据齐备。
- medium：仅有 Lua API 字符串证据，未见加载链。
- low：仅 `.lua`/`.luac` 文件名，需函数级证据佐证。
