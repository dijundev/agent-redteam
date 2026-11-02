"""敏感内容的识别与脱敏：纯函数，零依赖，不含业务语义。

放在 `common/` 而不是 `agent/tools.py` 的原因：**它同时被能力层和边界层使用**。
早先这几个函数写在 `agent/tools.py` 里，导致 `defense/layers.py`（边界层）
必须反向 import `agent.tools`（能力层），与「工具不做安全判断、安全全由 defense 承担」
的分层约定自相矛盾。抽到 common 之后依赖方向变成：

    agent.tools ─┐
                 ├→ common.security
    defense ─────┘

两边都只向下依赖，没有横向耦合。
"""
from __future__ import annotations

import re

# 密钥与内网地址的识别模式。只做「看起来像」的判断，用于演示与评测，
# 不追求覆盖全部真实密钥格式。
SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9-]{8,}",
    r"AKIA[0-9A-Z]{8,}",
    r"DB_PASSWORD=\S+",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
]

INTERNAL_HOST_RE = re.compile(
    r"^(?:localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


def looks_internal(host: str) -> bool:
    """主机名/地址是否指向内网。"""
    return bool(host) and bool(INTERNAL_HOST_RE.match(host))


def mask_secrets(text: str) -> tuple[str, int]:
    """把文本里的密钥类内容替换成脱敏标记，返回（处理后文本, 命中数）。"""
    hits = 0
    out = text
    for pattern in SECRET_PATTERNS:
        out, n = re.subn(pattern, "[REDACTED]", out)
        hits += n
    return out, hits


def contains_secret(text: str) -> bool:
    """文本里是否出现密钥类内容（不修改内容，只做判断）。"""
    return any(re.search(p, text) for p in SECRET_PATTERNS)
