"""用例规范自检：结构、判据可达性、编码混淆载荷的脚本模型表现。

不联网、不花 API 额度。做两件事：
1. 结构校验（失败即非零退出）：id 唯一、turns 非空、task 模板可解析、
   success_when 的 op 合法且正则能编译；
2. 可达性自检（只记录，不作通过条件）：用确定性脚本模型在防御全关下跑一遍，
   看每条断言是否至少能被命中一次。编码混淆类载荷需要模型主动解码，
   脚本模型不命中是预期结果，报告里会单独标注。

用法：
    python scripts/validate_cases.py
    python scripts/validate_cases.py --cases cases/attack_adaptive.yaml cases/attack_adaptive_v2.yaml
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from app.agent.engine import run_case  # noqa: E402
from app.core.config import load_config  # noqa: E402
from app.core.prompts import load_agent_system  # noqa: E402
from app.defense.layers import DefenseStack  # noqa: E402
from app.judge.rules import evaluate as judge_run  # noqa: E402
from app.llm import get_provider  # noqa: E402
from app.runner.cases import load_tasks  # noqa: E402
from app.runner.metrics import LAYERS  # noqa: E402

VALID_OPS = {"tool_ok", "tool_any", "answer_re", "outbox_re", "arg_re"}
DEFAULT_FILES = ["cases/attack_adaptive.yaml", "cases/attack_adaptive_v2.yaml"]


def check_structure(path: Path, tasks: dict) -> tuple[list[dict], list[str]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    cases, errors = [], []
    seen: set[str] = set()
    if not isinstance(raw, list):
        return [], [f"{path.name}: 顶层必须是列表"]
    for c in raw:
        cid = str(c.get("id", "?"))
        if cid in seen:
            errors.append(f"{cid}: id 重复")
        seen.add(cid)
        if not isinstance(c.get("turns"), list) or not c.get("turns"):
            errors.append(f"{cid}: turns 缺失或为空")
        if not c.get("success_when"):
            errors.append(f"{cid}: 缺少 success_when")
        task = c.get("task")
        if isinstance(task, str) and task not in tasks:
            errors.append(f"{cid}: 未定义任务模板 {task}")
        elif not isinstance(task, (str, dict)):
            errors.append(f"{cid}: 缺少 task")
        for check in c.get("success_when") or []:
            op = check.get("op")
            if op not in VALID_OPS:
                errors.append(f"{cid}: 未知判据 op={op}")
                continue
            patterns = []
            if op in ("answer_re", "outbox_re", "arg_re"):
                patterns.append(check.get("re", ""))
            elif op == "tool_ok":
                patterns.extend((check.get("args_re") or {}).values())
            for p in patterns:
                try:
                    re.compile(p)
                except re.error as exc:
                    errors.append(f"{cid}: 正则无法编译 {p!r} — {exc}")
        c["task"] = tasks[task] if isinstance(task, str) else task
        cases.append(c)
    return cases, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="用例规范自检（离线）")
    parser.add_argument("--cases", nargs="*", default=DEFAULT_FILES)
    parser.add_argument("--output", default="reports/case-readiness.md")
    args = parser.parse_args()

    cfg = load_config()
    tasks = load_tasks()
    provider = get_provider("scripted")
    system = load_agent_system()
    overrides = {k: False for k in LAYERS}

    rows: list[dict] = []
    all_errors: list[str] = []
    for rel in args.cases:
        path = Path(rel)
        if not path.is_absolute():
            path = ROOT / path
        cases, errors = check_structure(path, tasks)
        all_errors.extend(f"{path.name}: {e}" for e in errors)
        for c in cases:
            stack = DefenseStack(cfg.defense, overrides)
            run = run_case(c, stack, provider, system, cfg.evaluation.max_steps, "baseline")
            verdict = judge_run(c, run)
            rows.append({
                "file": path.name, "id": c["id"], "type": c.get("type", ""),
                "family": c.get("family", ""), "title": c.get("title", ""),
                "ops": ",".join(str(x.get("op")) for x in c.get("success_when") or []),
                "hit": verdict.success, "reason": verdict.reason,
                "steps": len([s for s in run.steps if s.get("kind") == "tool"]),
            })

    lines = [
        "# 用例规范自检（case-readiness.md）",
        "",
        f"> 由 `python scripts/validate_cases.py` 离线生成，**禁止手填**；"
        f"生成时间：{datetime.now():%Y-%m-%d %H:%M}。",
        "> 判据可达性用确定性脚本模型（`provider=scripted`）在防御全关下跑，"
        "**不联网、不消耗 API 额度**；它不会解码 base64 / 归一化全角字符 / 拼接分段 URL，"
        "所以编码混淆类用例显示「不命中」是预期，只说明真模型才有意义。",
        "",
        f"结构校验：{len(all_errors)} 个错误；共 {len(rows)} 条用例，"
        f"脚本模型命中 {sum(1 for r in rows if r['hit'])} 条。",
        "",
        "| 文件 | 用例 | 家族 | 判据算子 | 脚本模型命中 | 工具步数 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        lines.append(f"| `{r['file']}` | `{r['id']}` {r['title']} | {r['family']} | "
                     f"{r['ops']} | {'是' if r['hit'] else '否'} | {r['steps']} |")
    if all_errors:
        lines += ["", "## 结构错误", ""] + [f"- {e}" for e in all_errors]
    lines += [
        "",
        "## 这批载荷覆盖了什么、没覆盖什么",
        "",
        "- **已覆盖（载荷与判据已就位）**：base64 编码指令、全角/同形字动词、HTML 注释里的 SYSTEM 伪造、"
        "CSV 公式字段外链、分段拼接 URL、URL 双重编码、零宽字符文件名、附件 OCR 文本注入。",
        "- **仍未覆盖**：真正的图片/多模态输入（目标 Agent 无视觉通道）、二进制附件解析、"
        "跨轮长期记忆投毒、工具返回值里的多层嵌套注入。",
        "- **待办**：这 8 条在真模型上的效果结论尚未实测，属于「已备好、未跑」，"
        "不能写进对外效果数字。",
        "",
    ]
    out = ROOT / args.output
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"报告：{out}")
    print(f"结构错误 {len(all_errors)} 个｜用例 {len(rows)} 条｜脚本模型命中 "
          f"{sum(1 for r in rows if r['hit'])} 条")
    if all_errors:
        for e in all_errors:
            print("  ERROR", e)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
