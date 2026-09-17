---
name: golang
title: Go 样本静态分析方法论
source: docs/MalwareAnalysis/malware-analysis/arch_golang.md (v2.0)
applies_to: [language:golang]
priority: 90
max_tokens: 1200
---

# Go 样本静态分析方法论

## 适用条件
arch_detection.language = golang 的样本。Go 样本函数多、命名符号完整，关键是**聚类与噪声分层**。

## 识别特征（arch_detection 证据）
- 字符串中的 `go.buildid`、`go1.<ver>.<suffix>` 运行时版本号 → high。
- `main.` / `net/http.` / `github.com/` 包路径前缀 → 辅助证据。

## 三角验证法
任何行为结论必须三方印证，单方证据降级：
`strings.txt`（行为意图）→ `function_index.txt`（实现位置）→ `decompile/*.c`（实现细节）。
仅字符串命中标 medium；函数索引有对应符号可升 high。

## 自定义类型速查（读反编译必备）
- `GoString` = `{ptr, len}`；`GoSlice` = `{ptr, len, cap}`；`GoInterface` = `{type, data}` 双指针。
- 见到 `golang.org/x/` 与大量 `runtime.*` 调用即运行库噪声。

## 包路径聚类 = 行为组发现
按 `包路径/函数名` 前缀聚类，包名直接提示行为：
- `main.` 业务入口与 C2 逻辑；`net/http`、`crypto/tls` 通信；`os/exec` 命令执行；
- `encoding/base64`、`crypto/aes` 加解密；`golang.org/x/sys/windows` 系统调用。
优先分析 main 包与 net/http 相关族。

## 分层噪声过滤模型
- **绝对噪声**（永远跳过）：`runtime.`、`reflect.`、`type..`、`sync.`、GC/调度相关。
- **相对噪声**（抽代表验证）：`crypto/`、`encoding/` 标准库族。
- **基础设施**（低优先级）：日志、配置加载、错误处理包装。
- **业务逻辑**（分析重心）：main 包、C2、任务分发。

## 现代 Go 配置模式
viper/mapstructure/validator/cobra 痕迹（`Unmarshal`、`Execute`、`PersistentFlags` 字符串）说明样本有结构化配置；配置结构体 tag 常泄露字段语义。cobra 子命令名即能力清单。

## 字符串"四链路法"
字符串常量 → 引用函数（符号完整可直接查）→ 调用方 → goroutine 启动点（`go func` 关键字痕迹 `runtime.newproc`）。`.stmp_` 前缀是静态拼接字符串的编译器产物。

## interface 分发
`tab[1].inter` / `tab[1]._type` 读取即接口方法分发，跟进目标函数是还原插件/模块结构的捷径。

## 置信度规则
同三角验证：三方印证 high；两方 medium；仅字符串 low 并注明。
