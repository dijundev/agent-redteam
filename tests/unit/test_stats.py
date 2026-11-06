"""统计函数的固定值回归：Wilson 区间与 Fisher 精确检验。

这些数字直接出现在对外报告里，必须锁死。实现是纯 Python（本机没有 scipy），
用几组已知结果防止以后「顺手优化」把口径改掉。
"""
from __future__ import annotations

import pytest

from app.runner.stats import fisher_exact, fmt_p, verdict_at, wilson


@pytest.mark.parametrize(
    "k,n,expected",
    [
        (0, 60, (0.0, 6.02)),
        (3, 60, (1.71, 13.70)),
        (0, 48, (0.0, 7.41)),
        (13, 46, (17.32, 42.55)),
    ],
)
def test_wilson_known_values(k, n, expected):
    lo, hi = wilson(k, n)
    assert lo == pytest.approx(expected[0], abs=0.05)
    assert hi == pytest.approx(expected[1], abs=0.05)


def test_wilson_zero_samples():
    assert wilson(0, 0) == (0.0, 0.0)


def test_fisher_known_values():
    # 正式 60 条那组：不显著
    assert fisher_exact(3, 60, 0, 60) == pytest.approx(0.244, abs=0.005)
    # 加固版攻击集主效应：极显著
    assert fisher_exact(13, 46, 0, 48) == pytest.approx(3.4e-05, abs=1e-05)
    # 消融 ②：有信号但未达显著
    assert fisher_exact(3, 23, 0, 24) == pytest.approx(0.109, abs=0.005)


def test_fisher_symmetry_and_degenerate():
    assert fisher_exact(3, 23, 0, 24) == pytest.approx(fisher_exact(0, 24, 3, 23))
    assert fisher_exact(0, 22, 0, 24) == pytest.approx(1.0)
    assert fisher_exact(0, 0, 0, 10) == 1.0  # 无效输入不抛异常


def test_format_helpers():
    assert fmt_p(3.4e-05) == "<0.001"
    assert fmt_p(0.244).startswith("0.244")
    assert "达到" in verdict_at(0.001)
    assert "未达到" in verdict_at(0.244)
