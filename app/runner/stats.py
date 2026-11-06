"""评测统计：区间估计与显著性检验。

只放纯函数，不依赖 scipy（本机没装，也不想为两个函数加一个重依赖）。
`audit_real.py` 与 `adaptive_eval.py` 都从这里取，避免各写一份 Wilson/Fisher。

- Wilson 区间：小样本、命中数接近 0 时比 Wald 区间可靠；
- Fisher 精确检验：2×2 列联表，按「概率不超过观测表的表」求和的双侧 p 值，
  样本小、有零格时比卡方检验合适。
"""
from __future__ import annotations

import math
from math import comb


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """二项比例的 Wilson 置信区间，返回百分数。"""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, (centre - half) * 100), min(100.0, (centre + half) * 100))


def fisher_exact(hit1: int, n1: int, hit2: int, n2: int) -> float:
    """双侧 Fisher 精确检验 p 值。

    表为 [[hit1, n1-hit1], [hit2, n2-hit2]]；固定边际下枚举所有可能表，
    把概率 <= 观测表概率的都加起来。零格（如 0/48）也能算。
    """
    if n1 <= 0 or n2 <= 0 or hit1 < 0 or hit2 < 0 or hit1 > n1 or hit2 > n2:
        return 1.0
    total = n1 + n2
    hits = hit1 + hit2
    denom = comb(total, hits)
    low = max(0, hits - n2)
    high = min(n1, hits)

    def prob(x: int) -> float:
        if x < low or x > high:
            return 0.0
        return (comb(n1, x) * comb(n2, hits - x)) / denom

    observed = prob(hit1)
    p = sum(prob(x) for x in range(low, high + 1)
            if prob(x) <= observed * (1 + 1e-12))
    return min(1.0, p)


def fmt_p(p: float) -> str:
    if p < 0.001:
        return "<0.001"
    if p < 0.01:
        return f"{p:.4f}"
    return f"{p:.3f}"


def verdict_at(p: float, alpha: float = 0.05) -> str:
    """只写「是否达到显著」，不写「证明有效」——统计检验不能证明因果。"""
    return ("达到" if p < alpha else "未达到") + f" p<{alpha:g} 显著"
