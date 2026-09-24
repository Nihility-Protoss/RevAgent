import math
from typing import Dict, Any


def calculate_entropy(data: bytes) -> Dict[str, Any]:
    """计算字节序列的 Shannon 熵。

    参数：
        data: 待分析的字节序列。

    返回：
        包含 status、entropy 值（0.0-8.0）和 interpretation 的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "entropy": 0.0,
        "interpretation": "",
        "byte_count": len(data),
    }

    try:
        if len(data) == 0:
            result["interpretation"] = "empty_data"
            return result

        # 统计字节频率
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1

        # 计算 Shannon 熵
        entropy = 0.0
        data_len = len(data)
        for count in frequency:
            if count == 0:
                continue
            p = count / data_len
            entropy -= p * math.log2(p)

        result["entropy"] = round(entropy, 4)

        # 依据 arch_windows_pe.md 的分档给出解释
        if entropy < 4.0:
            result["interpretation"] = "low_entropy: likely unencrypted data or code"
        elif entropy < 6.5:
            result["interpretation"] = "normal_entropy: typical code segment"
        elif entropy < 7.5:
            result["interpretation"] = "high_entropy: likely compressed (UPX-like packer)"
        else:
            result["interpretation"] = "very_high_entropy: likely encrypted or strongly compressed"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result
