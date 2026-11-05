"""单条用例探针：打印真实模型下的完整轨迹与每步耗时。

用法：
    python scripts/probe_one.py B01 hardened
    python scripts/probe_one.py D01 baseline

用途：换模型/换网关后先跑一条，确认工具协议、判定与耗时，再开全量。
"""

import sys
import time
from pathlib import Path

# 直接 `python scripts/probe_one.py` 时 sys.path[0] 是 scripts/，把项目根补进去
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.agent.engine import run_case
from app.core.config import load_config
from app.core.prompts import load_agent_system, load_prompt
from app.defense.layers import DefenseStack
from app.judge.rules import benign_ok, evaluate as judge_run
from app.llm import get_provider
from app.runner.cases import load_attacks, load_benign

LAYERS = ["isolation", "allowlist", "params", "gate", "filter"]


def main() -> None:
    case_id = sys.argv[1] if len(sys.argv) > 1 else "B01"
    config = sys.argv[2] if len(sys.argv) > 2 else "hardened"

    cfg = load_config()
    provider = get_provider("deepseek", **cfg.provider_kwargs("deepseek"))
    overrides = {name: config == "hardened" for name in LAYERS}
    stack = DefenseStack(cfg.defense, overrides)

    pool = {c["id"]: c for c in load_attacks()}
    benign = {c["id"]: c for c in load_benign(cfg.evaluation.benign_path)}
    case = pool.get(case_id) or benign.get(case_id)
    if not case:
        raise SystemExit(f"找不到用例 {case_id}")

    print(f"用例 {case_id} · 配置 {config} · 模型 {cfg.deepseek.get('model')}", flush=True)
    started = time.time()
    run = run_case(case, stack, provider, load_agent_system(),
                   cfg.evaluation.max_steps, config)
    wall = time.time() - started

    for step in run.steps:
        if step["kind"] == "tool":
            print("  TOOL  %-14s %s ok=%s blocked=%s %s" % (
                step.get("tool"), step.get("args"), step.get("ok"),
                step.get("blocked_by"), (step.get("reason") or "")[:60]), flush=True)
        else:
            print("  FINAL %r" % ((step.get("text") or "")[:160],), flush=True)

    if case.get("type") == "benign":
        ok, reason = benign_ok(case, run)
        print(f"判定：正常任务 {'通过' if ok else '失败'} — {reason}")
    else:
        verdict = judge_run(case, run)
        print(f"判定：{'被攻破' if verdict.success else '防住'} — {verdict.reason}")

    print(f"耗时 {wall:.1f}s · 模型调用 {provider.usage}")


if __name__ == "__main__":
    main()
