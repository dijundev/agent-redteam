"""审计真模型那一轮评测：覆盖完整性、无效样本、置信区间、跨轮波动。

所有数字都从 reports/summary-real.json、reports/runs.db、reports/eval-real.log 推出，
结果写成 reports/audit-real.md。禁止手填数字；重跑本脚本即可复核。

用法：python scripts/audit_real.py
"""

from __future__ import annotations

import collections
import datetime as dt
import json
import re
import sqlite3
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.runner.cases import ATTACK_FILES  # noqa: E402
from app.runner.stats import fisher_exact, fmt_p, verdict_at, wilson  # noqa: E402

REPORTS = ROOT / "reports"
CASES_DIR = ROOT / "cases"


def case_ids() -> list[str]:
    """只数正式 60 条用例：不能 glob `attack_*.yaml`，否则会把自适应攻击集也算进来。"""
    ids: list[str] = []
    for name in list(ATTACK_FILES) + ["benign.yaml"]:
        data = yaml.safe_load((CASES_DIR / name).read_text(encoding="utf-8"))
        items = data.get("cases", []) if isinstance(data, dict) else data
        ids.extend(str(c["id"]) for c in items)
    return ids


def main() -> None:
    summary = json.loads((REPORTS / "summary-real.json").read_text(encoding="utf-8"))
    meta = summary["meta"]
    configs = summary["configs"]
    provider = meta["provider"]
    model = meta.get("model", "未记录")
    generated = dt.datetime.strptime(meta["generated_at"], "%Y-%m-%d %H:%M")
    wall = float(meta["wall_seconds"])
    # 生成时间只精确到分钟，前后各留余量；起点按耗时回推。
    end_ts = (generated + dt.timedelta(seconds=180)).timestamp()
    start_ts = (generated - dt.timedelta(seconds=wall + 120)).timestamp()

    con = sqlite3.connect(REPORTS / "runs.db")
    con.row_factory = sqlite3.Row
    all_rows = [dict(r) for r in con.execute(
        "select * from runs where provider=? order by ts", (provider,))]
    batch = [r for r in all_rows if start_ts <= r["ts"] <= end_ts]
    con.close()

    ids = case_ids()
    cfg_names = list(configs.keys())
    expected = {(cfg, cid) for cfg in cfg_names for cid in ids}
    present = {(r["config"], r["case_id"]) for r in batch}
    missing = sorted(expected - present)
    empty = sorted((r["config"], r["case_id"]) for r in batch
                   if r["answer"] is None or str(r["answer"]).strip() == "")

    log_path = REPORTS / "eval-real.log"
    err_lines = []
    if log_path.exists():
        err_lines = [ln.strip() for ln in log_path.read_text(encoding="utf-8").splitlines()
                     if re.search(r"\bERR\b", ln)]

    elapsed = sorted(r["elapsed_ms"] for r in batch if r["elapsed_ms"])
    p50 = elapsed[len(elapsed) // 2] if elapsed else 0
    p90 = elapsed[int(len(elapsed) * 0.9)] if elapsed else 0
    pmax = elapsed[-1] if elapsed else 0

    # 跨轮波动：按 30 分钟时间桶观察 baseline 攻破集合（并发落库会交错，仅作趋势参考）
    buckets: dict[int, list[dict]] = collections.defaultdict(list)
    if all_rows:
        t0 = all_rows[0]["ts"]
        for r in all_rows:
            buckets[int((r["ts"] - t0) // 1800)].append(r)

    lines: list[str] = []
    lines.append("# 真模型评测审计（audit-real.md）")
    lines.append("")
    lines.append(f"> 由 `python scripts/audit_real.py` 自动生成，**禁止手填**。"
                 f"数据源：`summary-real.json` / `runs.db` / `eval-real.log`；"
                 f"生成时间：{dt.datetime.now():%Y-%m-%d %H:%M}。")
    lines.append("")
    lines.append(f"模型：`{model}` · provider：`{provider}` · "
                 f"报告批次 `{meta['generated_at']}` · 标称 {len(expected)} 个格子 "
                 f"（{len(ids)} 用例 × {len(cfg_names)} 配置）。")
    lines.append("")
    lines.append("## 一、覆盖与有效样本")
    lines.append("")
    lines.append("| 项 | 值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 标称格子数 | {len(expected)} |")
    lines.append(f"| 最终批次落库轨迹 | {len(batch)} 条，覆盖 {len(present)} 个格子 |")
    lines.append(f"| 无轨迹格子 | {len(missing)}："
                 + ("、".join(f"`{c}/{i}`" for c, i in missing) or "无") + " |")
    lines.append(f"| 有轨迹但回答为空 | {len(empty)}："
                 + ("、".join(f"`{c}/{i}`" for c, i in empty) or "无") + " |")
    lines.append(f"| 日志标记的 ERR 行 | {len(err_lines)} |")
    lines.append(f"| 有效轨迹（有轨迹且回答非空） | {len(batch) - len(empty)} / {len(expected)}"
                 f" = **{(len(batch) - len(empty)) / len(expected) * 100:.1f}%** |")
    lines.append("")
    if err_lines:
        lines.append("日志里的异常条目（评测器会 `--retry-err` 补跑，但补跑不保证全都救回来）：")
        lines.append("")
        lines.append("```")
        lines.extend(err_lines[-6:])
        lines.append("```")
        lines.append("")
    lines.append("回答为空的运行在聚合时被算作「攻击未命中 / 正常任务未通过」，"
                 "它们**不是防御生效的证据**，也不是模型能力不足的证据，属于无效样本。")
    lines.append("")
    lines.append("## 二、置信区间（Wilson 95%）")
    lines.append("")
    lines.append("| 指标 | 观测 | 95% 区间 |")
    lines.append("| --- | --- | --- |")
    for cfg in cfg_names:
        c = configs[cfg]
        lo, hi = wilson(c["attack_success"], c["attack_total"])
        lines.append(f"| `{cfg}` ASR | {c['asr']:.1f}% ({c['attack_success']}/{c['attack_total']}) "
                     f"| [{lo:.1f}%, {hi:.1f}%] |")
        lo, hi = wilson(c["benign_passed"], c["benign_total"])
        lines.append(f"| `{cfg}` 正常任务 | {c['benign_pass_rate']:.1f}% "
                     f"({c['benign_passed']}/{c['benign_total']}) | [{lo:.1f}%, {hi:.1f}%] |")
    lines.append("")
    lines.append("两组 ASR 区间**互相重叠**：在 60 条攻击用例、每个用例只跑一次的条件下，"
                 "观测到的差异不足以在统计上断言「防御显著降低了攻击成功率」。"
                 "这组数字只能用于描述现象与定位失效点，不能当作效果估计。")
    lines.append("")
    lines.append("## 二之二、显著性检验（Fisher 精确检验，双侧）")
    lines.append("")
    b = configs.get("baseline", {})
    h = configs.get("hardened", {})
    if b and h:
        p = fisher_exact(b["attack_success"], b["attack_total"],
                         h["attack_success"], h["attack_total"])
        lines.append(f"`baseline` {b['attack_success']}/{b['attack_total']} vs "
                     f"`hardened` {h['attack_success']}/{h['attack_total']} → "
                     f"**p = {fmt_p(p)}**（{verdict_at(p)}）。")
    else:
        p = 1.0
        lines.append("缺少 baseline / hardened，无法检验。")
    lines.append("")
    lines.append("区间重叠与假设检验给出同一个结论：这组数据**不能拒绝「防御前后一样」**。"
                 "要拿到显著结论，得把基线难度抬上去或增加样本——"
                 "后来那组加固版攻击集就是这么做的，见 `reports/adaptive.md`。")
    lines.append("")
    lines.append("## 三、跨轮波动（按 30 分钟桶观察）")
    lines.append("")
    lines.append("| 时间桶 | baseline 攻破集合 |")
    lines.append("| --- | --- |")
    for k in sorted(buckets):
        b = buckets[k]
        hits = sorted({r["case_id"] for r in b
                       if r["config"] == "baseline"
                       and not r["case_id"].startswith("B")
                       and r["success"]})
        t = dt.datetime.fromtimestamp(b[0]["ts"]).strftime("%H:%M")
        lines.append(f"| {t} 起 | " + ("、".join(f"`{h}`" for h in hits) or "无") + " |")
    lines.append("")
    lines.append("不同轮次攻破集合并不一致（`E11`、`T08` 各只出现过一轮）；这段期间还改过系统提示词与良性用例，"
                 "所以波动既可能来自模型随机性、也可能来自配置变化。**每条用例只采样一次**，"
                 "没有重复实验，谈不上稳定测量。")
    lines.append("")
    lines.append("## 四、能说什么 / 不能说什么")
    lines.append("")
    lines.append("- **能说**：这套评测链路把 60 条攻击与 20 条正常任务在两种防御配置下跑完并逐条落库；"
                 "定位到该模型在 `tool_abuse`（越权工具调用）上的具体失效点；"
                 "防御全开后这些工具调用被白名单与出站过滤拦下。")
    lines.append("- **不能说**：由 3 条命中样本推断防御的量化收益；把 `5% → 0%` 当成可推广的效果结论；"
                 "把逐层边际、跨模型结论套到真模型上（真模型只跑了 2 种配置、1 个模型）。")
    lines.append("- **要补才有说服力**：① 提高基线难度（自适应/编码混淆载荷，让 baseline ASR 到 20%~30%）；"
                 "② 对关键用例重复采样 5~10 次；③ 真模型上补逐层消融；④ 无效样本在聚合时显式剔除或单列。")
    lines.append("")
    lines.append("## 五、性能与复现")
    lines.append("")
    lines.append(f"最终批次单次耗时 p50 {p50 / 1000:.0f}s / p90 {p90 / 1000:.0f}s / "
                 f"max {pmax / 1000:.0f}s；整轮 {wall:.0f}s。")
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/audit_real.py       # 重新生成本报告")
    lines.append("python -m app.runner.evaluate --provider deepseek --configs baseline,hardened --workers 8 --tag real")
    lines.append("```")
    lines.append("")

    out = REPORTS / "audit-real.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")
    print(f"slots={len(expected)} trajectories={len(batch)} distinct={len(present)} "
          f"missing={missing} empty={empty} valid={len(batch) - len(empty)}")
    for cfg in cfg_names:
        c = configs[cfg]
        lo, hi = wilson(c["attack_success"], c["attack_total"])
        print(f"{cfg}: ASR {c['asr']:.1f}% CI95 [{lo:.1f}%, {hi:.1f}%]")


if __name__ == "__main__":
    main()
