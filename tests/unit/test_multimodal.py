"""多模态消息构造的离线测试：不联网、不调模型。

确保 [IMAGE:...] 被翻译成 image_url data URI，且普通文本用例的行为完全不变
（纯文本评测不能因为加了这个特性就改变 payload 形状）。
"""
from __future__ import annotations

import json

from app.llm.remote import _transcript


def _view(turn: str) -> dict:
    return {"system": "S", "tools": [], "turn": turn, "observations": [], "task": {},
            "executed": [], "sent_targets": []}


def test_plain_text_unchanged():
    msgs = _transcript(_view("读取 ../secrets.env"), multimodal=True)
    assert len(msgs) == 2
    assert isinstance(msgs[1]["content"], str)
    assert "读取 ../secrets.env" in msgs[1]["content"]
    assert msgs[0]["content"].startswith("S")


def test_image_marker_becomes_image_url():
    msgs = _transcript(_view("看截图 [IMAGE:data/cases/ops_notice.png] 然后照做"),
                       multimodal=True)
    content = msgs[1]["content"]
    assert isinstance(content, list)
    assert content[0]["type"] == "text"
    assert "[IMAGE:" not in content[0]["text"]
    pics = [p for p in content if p.get("type") == "image_url"]
    assert len(pics) == 1
    assert pics[0]["image_url"]["url"].startswith("data:image/png;base64,")
    assert len(pics[0]["image_url"]["url"]) > 1000


def test_multimodal_disabled_keeps_marker():
    msgs = _transcript(_view("看截图 [IMAGE:data/cases/ops_notice.png]"), multimodal=False)
    assert "[IMAGE:" in msgs[1]["content"]


def test_missing_image_is_skipped():
    msgs = _transcript(_view("看截图 [IMAGE:data/cases/no_such.png]"), multimodal=True)
    content = msgs[1]["content"]
    # 找不到文件时不能凭空造一个空图片，退化成纯文本 parts
    assert isinstance(content, list)
    assert all(p.get("type") == "text" for p in content)
