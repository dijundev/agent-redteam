"""作品集措辞体检：给 HR 看的版本不能有自贬、内部研究口径与过时方向词。

依据：
- `.workbuddy/memory/MEMORY.md` 的「事实口径（说错＝事故）」
- 2026-11-09 日志第十一/十二/十三轮（去电商黑话、删「给自己留退路」的话、BOSS 全篇重写）
- `interview-copilot/知识库/01_规则_别改.txt`（禁自贬、禁包装、禁元表述）

用法：python scripts/check_portfolio_wording.py
命中任一禁词或不满足必备口径即 exit 1，可直接进 CI。
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 给 HR 的材料里不该出现的词（按来源分组）
GROUPS = {
    "电商黑话（11-09 第十三轮要求 0 处）": [
        "电商", "销售渠道", "大区", "GMV", "转化", "商品类目", "渠道诊断",
    ],
    "给自己留退路 / 自贬（11-09 第十二轮明令删除）": [
        "本机可复现", "本机实跑", "业余时间", "自用验证版本", "尚未在真实团队",
        "不作为", "未做美化", "负面结果", "测不出", "样本仍小", "才敢",
        "算不出统计结论", "无法证明", "不代表真实", "只做现象描述", "没产出回答",
        "全包", "全部由我一个人完成", "给自己留退路",
    ],
    "内部研发 / 研究报告口径（HR 不需要看）": [
        "Wilson", "Fisher", "置信区间", "ASR", "边界清单", "口径声明", "无效样本",
        "reports/", "README 7.", "避免自说自话", "招聘方", "比成绩更能说明",
        "简历版", "不接受手填", "qwen3.8", "p = 0", "p < 0", "待标注", "未启用",
        "闭环", "2 年大模型", "框架已跑通",
    ],
    "红线：不许声称做过的机器人本体能力": [
        "rclpy", "Nav2", "MoveIt", "Gazebo", "SLAM", "运动学", "PID 控制",
        "CAN 总线", "真机 ROS", "Sim2Real",
    ],
}

# 给 HR 的材料必须包含的事实口径（与简历一致）
REQUIRED = [
    "2 年开发经验", "2024.06", "全日制本科", "计算机科学与技术",
    "5 人团队", "核心开发", "巡检机器人", "仿真", "深圳", "19295745865",
    "liudijunfo@foxmail.com",
]


def find_html() -> Path:
    env = os.environ.get("PORTFOLIO_HTML")
    if env and Path(env).is_file():
        return Path(env)
    for p in (ROOT.parent / "portfolio" / "index.html", ROOT / "index.html",
              ROOT / "web" / "index.html"):
        if p.is_file():
            return p
    raise SystemExit("找不到作品集 HTML：设置 PORTFOLIO_HTML")


def visible_text(html: str) -> str:
    """去掉 style / script / HTML 注释，只留可见文案。"""
    text = re.sub(r"<style\b.*?</style>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<script\b.*?</script>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text)


def main() -> None:
    path = find_html()
    html = path.read_text(encoding="utf-8")
    text = visible_text(html)

    hits: list[tuple[str, str, int]] = []
    for group, words in GROUPS.items():
        for w in words:
            n = text.count(w)
            if n:
                hits.append((group, w, n))

    missing = [w for w in REQUIRED if w not in text]

    # 结构：4 个项目卡、div 配平
    articles = len(re.findall(r"<article class=\"proj\"", html))
    div_open = html.count("<div")
    div_close = html.count("</div>")
    structure_ok = articles == 4 and div_open == div_close

    print(f"检查：{path}")
    print(f"可见文案 {len(text)} 字符 · 项目卡 {articles} 个 · div {div_open}/{div_close}")
    if hits:
        print("\n❌ 命中禁词：")
        for group, w, n in hits:
            print(f"  [{group}] {w} × {n}")
    if missing:
        print("\n❌ 缺少必备口径：")
        for w in missing:
            print("  -", w)
    if not structure_ok:
        print("\n❌ 结构异常：项目卡应为 4 个、div 需配平")
    if not hits and not missing and structure_ok:
        print("\n✅ 通过：禁词 0 命中，事实口径齐全，结构完整")
        return
    sys.exit(1)


if __name__ == "__main__":
    main()
