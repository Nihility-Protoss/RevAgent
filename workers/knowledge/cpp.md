---
name: cpp
title: C/C++ 样本静态分析方法论
source: docs/MalwareAnalysis/malware-analysis/arch_cpp.md (v1.1)
applies_to: [language:c_cpp]
priority: 90
max_tokens: 1200
---

# C/C++（MSVC/GCC）样本静态分析方法论

## 适用条件
arch_detection.language = c_cpp 的样本，与 windows_pe 基线叠加。

## 核心原则：OLLVM 选择性保护
商业壳/OLLVM 通常只保护核心逻辑函数。判读规则：
- **反编译失败、CFG 呈放射状/平坦化的函数 → 高价值目标**，优先入选深度分析候选。
- **反编译成功但体积极大（数千行）、满是 STL 模板噪声的函数 → 大概率是基础设施噪声**，降低优先级。
不要把时间花在逐行阅读 STL 实现上。

## 噪声分离：函数族分类
不要逐函数定性。按函数族批量归类，每族抽 3-5 个代表验证即可：
- STL 容器族（`std::vector/map/string` 痕迹：大量 `??0?$` 风格命名或模板实例化）。
- CRT/运行库族（`malloc/free/printf` 包装、`__security_check_cookie`）。
- 字符串与工具族（`strlen` 包装、大小写转换、Base64/编码例程）。
- 业务逻辑族（调用 WinAPI、访问全局配置缓冲区、参与命令分发）——分析重心。

## 对象还原要点
- vftable 写入：构造函数首段向 `this+0` 写入常量指针即虚表地址，可恢复类名与继承关系。
- `this` 指针约定：RCX（64 位）/ECX（32 位），成员变量偏移 `this+8`、`this+10` 等。
- 对象数组：连续构造调用 + 固定步长指针递增。

## STL 痕迹速查
- SSO 阈值：`std::string` 容量 ≤15、`std::wstring` ≤7 时数据存对象内，无堆分配。
- `std::map/set`：红黑树，`_Left/_Right/_Parent` 三连指针 + `_Isnil` 哨兵。
- `std::shared_ptr`：双指针（对象 + 控制块），控制块头部为引用计数对。

## 命名建议
- 恢复出虚表后：按 vftable 符号或首个虚函数语义命名，如 `CConfigParser_vtbl`。
- 未还原的调度函数：`sub_401230_cmd_dispatcher` 风格，注明判读依据。

## 置信度规则
- high：vftable 符号、SSO 阈值、模板实例化命名等硬性编译器痕迹。
- medium：函数族归类（基于调用模式推断）。
- low：对象语义的推测性还原，必须标注"推测"。
