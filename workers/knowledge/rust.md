---
name: rust
title: Rust 样本静态分析方法论
source: docs/MalwareAnalysis/malware-analysis/arch_rust.md (v2.0)
applies_to: [language:rust]
priority: 90
max_tokens: 1200
---

# Rust 样本静态分析方法论

## 适用条件
arch_detection.language = rust 的样本。Rust 样本函数常达数万级：**禁止遍历全部反编译文件，禁止逐状态逆向**。

## 识别特征（arch_detection 证据）
- `/rustc/<hash>/` 编译器路径、`src\*.rs` 源码路径（字符串中直接可见）。
- panic 指纹：`core::panicking::panic`、`unwrap failed`、`index out of bounds`。
- 以上出现即 high 置信度；只有 `.rs` 路径无 rustc 标记为 medium。

## Phase 式噪声过滤
1. **函数族归类**：按源码路径前缀聚类（`src\network\`、`src\exec\`），族名即行为提示。
2. **I/O 边界扫描**：只在函数索引/字符串层面找 WinAPI、文件路径、URL 的引用函数，其余不读。
3. **按需深入**：仅对入选候选读取反编译片段。

## Rust 内存布局（读反编译必备）
- `String`/`Vec<T>` = `{ptr, len, cap}` 三连（24 字节）。
- slice `&[T]` = `{ptr, len}` 16 字节。
- `Option<Result<T>>` 常编码为判别字节 + 联合；枚举判别值是状态机还原关键。
- 闭包 = 环境捕获结构体 + 函数指针。

## 五大高频恶意模式
1. **内存执行**：申请 RWX/RW→RX 内存 + 写入 + 线程启动，对应 `memexec` 族函数。
2. **CFF + 诱饵**：大量条件分支中仅少数真实路径（平坦化），真实分支伴随敏感 API。
3. **伪装配置**：硬编码"正常软件"配置字符串掩护真实 C2 配置，两者结构同构。
4. **环境变量反调试**：读取 `DEBUG`、`RUST_BACKTRACE` 等决定行为分支。
5. **Command 执行**：`std::process::Command` 构造链（`new` → `arg` 连续调用）。

## 字符串解密三模式
- 字节数组 + XOR/ADD 常量循环（Rust 常以迭代器 `map` 形式出现）。
- `include_bytes!` 嵌入密文 + 运行时 `decrypt` 函数族。
- 分段拼接：`concat!` 多段常量，明文中找片段即可关联。

## 命名建议
按 `crate::module` 路径命名函数族，如 `net_http_client::request`；无路径的候选标注 `rust_` 前缀与判读依据。

## 置信度规则
同 windows_pe 基线；源码路径映射到行为角色（如 `src\c2\` → C2 逻辑）属 medium，需反编译片段佐证才升 high。
