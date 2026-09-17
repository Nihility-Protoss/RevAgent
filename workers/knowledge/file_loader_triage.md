---
name: file_loader_triage
title: 文件加载型样本快速定位方法论
source: docs/MalwareAnalysis/malware-analysis/analysis-guides/file_loader_quick_triage.md
applies_to: [sample_form:exe_file_loader]
priority: 80
max_tokens: 1200
---

# 文件加载型样本快速定位方法论

## 适用条件
样本形态判定为 exe_file_loader：EXE 主程序，strings 中出现第二个 PE/载荷文件名、MZ 头、`This program cannot be run in DOS mode` 或大量无引用的密文字节数组。

## 目标：只定位三个关键地址
1. **读取点**：文件/资源被读入内存的位置（CreateFile/ReadFile/资源加载 API 附近）。
2. **解密完成点**：密文变为明文载荷的位置（解码循环出口，缓冲区内容呈现 MZ/`7z`/合法头）。
3. **执行点**：载荷被转交 CPU 的位置（CreateThread/QueueUserAPC/SetThreadContext，或修改既有线程）。

## 反向定位法（无 xrefs 时的静态近似）
正向跟丢时反向收敛：从 strings 中的载荷文件名/资源名出发，在 function_index 或反编译片段中查找引用该字符串的函数；该函数即读取点候选。读取点找到后沿调用链向下找分配→解密→执行。

## 五段式行为链条（判定核心逻辑函数的 checklist）
①**读取/定位**（文件、资源节、硬编码缓冲区）→ ②**内存分配**（VirtualAlloc/GlobalAlloc，注意 flProtect 参数 RW vs RX 的时序）→ ③**解密/解压**（XOR/RC4/AES 循环；LZ 解压头特征）→ ④**保护修改**（VirtualProtect 改 RX，写时保护 RW 是加壳特征）→ ⑤**转交执行**（线程/APC/入口点调用）。
候选函数命中 ≥3 段即为核心逻辑函数，置信度 high。

## 解密算法静态识别
- XOR：紧凑循环 `buf[i] ^= key`（key 为 1-4 字节常量或滚动密钥）。
- RC4：S 盒初始化双重循环（256 次交换）+ KSA/PRGA 特征。
- AES：S 盒常量表（`0x63, 0x7c, 0x77...`）出现在 .rdata。
- LZ 类：循环内位操作 + 长度距离对解码。

## 静态验证清单（无需动调）
反编译片段中出现以下任两项，即可确认载荷处理逻辑：
- 缓冲区写入后紧跟 MZ/`4D 5A` 或 `7z`/PE 头比较。
- VirtualProtect 调用且 flNewProtect ∈ {0x20 (RX), 0x40 (RWX), 0x04}。
- CreateThread/CreateRemoteThread 的 lpStartAddress 指向前述缓冲区。
- 解码循环出口处缓冲区长度与载荷大小一致。

## 记录格式
结论写入 artifact 时按 `{读取点: <addr>, 解密点: <addr>, 执行点: <addr>, 加密算法: <algo>, 置信度: <level>, 证据: [...]}` 组织，供 Phase 3 优先分析这三个函数。

## 置信度规则
链条命中 ≥3 段 = high；命中 2 段 = medium（需 Phase 3 反编译佐证）；仅字符串关联 = low。
