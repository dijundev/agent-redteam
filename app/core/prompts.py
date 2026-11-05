"""提示词从 prompts/*.md 读取，不在代码里写长字符串。"""
from __future__ import annotations

from functools import lru_cache

from app.common.paths import DATA_DIR, PROMPTS_DIR


@lru_cache(maxsize=16)
def load_prompt(name: str) -> str:
    path = PROMPTS_DIR / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"缺少提示词：{path}")
    return path.read_text(encoding="utf-8").strip()


def load_agent_system() -> str:
    """目标 Agent 的 system prompt：基础提示 + 当前可读文档清单。

    注入清单不是为了「让模型变聪明」，而是为了**不污染误杀率**：文档问答类正常任务
    如果因为模型不知道文件名而失败，测出来的就不是「防御有没有误伤」，而是
    「模型会不会猜文件名」。真实产品里这份清单来自文档索引，这里直接扫描 data/docs。
    """
    base = load_prompt("agent_system")
    docs_dir = DATA_DIR / "docs"
    if not docs_dir.is_dir():
        return base
    names = sorted(p.name for p in docs_dir.glob("*.md"))
    if not names:
        return base
    listing = "\n".join(f"- docs/{name}" for name in names)
    return f"{base}\n\n可用文档（路径相对 data/）：\n{listing}"
