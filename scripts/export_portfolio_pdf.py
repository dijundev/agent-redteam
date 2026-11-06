"""把线上作品集导出成可下载的 PDF（可复现，不依赖手工点「打印」）。

设计约束：
- 路径全部相对脚本目录 / 环境变量 / 多候选探测，不写死盘符、用户名、工作区；
- HTML 源优先取当前仓库 `gh-pages` 分支的 index.html（线上权威版本），
  取不到再退回相邻 `portfolio/index.html` 或 `PORTFOLIO_HTML` 指定的文件；
- Edge 路径从 `EDGE_PATH` 环境变量与常见安装位置探测；
- 导出前注入打印版样式：展开所有 `<details>`、强制打印背景色，
  否则纸面上会漏掉折叠区内容、浅色底纹也会丢。

用法：
    python scripts/export_portfolio_pdf.py --out <目标 pdf 路径>
    python scripts/export_portfolio_pdf.py --html <本地 html> --out <目标 pdf 路径>
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PRINT_CSS = """<style>
@media print{ html,body{ -webkit-print-color-adjust:exact; print-color-adjust:exact } }
details>.detail{display:block!important}
</style>"""


def from_git_gh_pages() -> str | None:
    """线上权威版本：直接读 gh-pages 分支的 index.html，避免本地源落后。"""
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "show", "gh-pages:index.html"],
            capture_output=True, timeout=30,
        )
        if out.returncode == 0 and out.stdout:
            return out.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def find_html(explicit: str | None) -> tuple[str, str]:
    if explicit:
        p = Path(explicit)
        if not p.is_absolute():
            p = ROOT / p
        if p.is_file():
            return p.read_text(encoding="utf-8"), str(p)
        raise SystemExit(f"找不到指定 HTML：{p}")
    env = os.environ.get("PORTFOLIO_HTML")
    if env and Path(env).is_file():
        return Path(env).read_text(encoding="utf-8"), env
    text = from_git_gh_pages()
    if text:
        return text, "gh-pages:index.html"
    for p in (ROOT.parent / "portfolio" / "index.html", ROOT / "index.html",
              ROOT / "web" / "index.html"):
        if p.is_file():
            return p.read_text(encoding="utf-8"), str(p)
    raise SystemExit("找不到作品集 HTML：设置 PORTFOLIO_HTML 或用 --html 指定")


def find_edge() -> Path:
    env = os.environ.get("EDGE_PATH")
    if env and Path(env).is_file():
        return Path(env)
    names = [
        r"Microsoft\Edge\Application\msedge.exe",
        r"Google\Chrome\Application\chrome.exe",
    ]
    roots = [
        os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"),
        os.environ.get("LOCALAPPDATA"), os.environ.get("ProgramW6432"),
    ]
    for root in filter(None, roots):
        for name in names:
            p = Path(root) / name
            if p.is_file():
                return p
    raise SystemExit("找不到 Edge/Chrome：设置 EDGE_PATH 指向 msedge.exe / chrome.exe")


def count_pages(pdf: Path) -> int:
    data = pdf.read_bytes()
    return len(re.findall(rb"/Type\s*/Page[^s]", data))


def main() -> None:
    parser = argparse.ArgumentParser(description="导出作品集 PDF")
    parser.add_argument("--html", default=None, help="作品集 HTML（默认取 gh-pages:index.html）")
    parser.add_argument("--out", default=None, help="输出 PDF 路径（默认 <仓库>/portfolio.pdf）")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    html, source = find_html(args.html)
    pdf = Path(args.out) if args.out else ROOT / "portfolio.pdf"
    if not pdf.is_absolute():
        pdf = ROOT / pdf
    pdf.parent.mkdir(parents=True, exist_ok=True)

    printable = html.replace("<details>", "<details open>")
    if "</head>" in printable:
        printable = printable.replace("</head>", PRINT_CSS + "</head>", 1)

    # Edge 的 Crashpad 子进程会短暂占住 profile 目录，TemporaryDirectory 自动清理
    # 会抛 WinError 145；用 mkdtemp + 忽略清理失败，临时目录留在系统 temp 里不影响结果。
    tmp_dir = Path(tempfile.mkdtemp(prefix="portfolio_pdf_"))
    try:
        page = tmp_dir / "portfolio_print.html"
        page.write_text(printable, encoding="utf-8")
        profile = tmp_dir / "edge_profile"
        edge = find_edge()
        cmd = [
            str(edge), "--headless", "--disable-gpu", "--no-sandbox",
            "--no-first-run", "--no-default-browser-check", "--no-pdf-header-footer",
            "--virtual-time-budget=15000", f"--user-data-dir={profile}",
            f"--print-to-pdf={pdf}", page.as_uri(),
        ]
        if pdf.exists():
            pdf.unlink()
        # Edge 会把渲染交给子进程后让主进程提前退出：用 subprocess.run 等主进程
        # 会立刻往下走、把 profile 目录删掉，结果 exit=0 但零产出。
        # 改成等「PDF 文件出现且连续几次大小不变」，再收尾。
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + args.timeout
        last_size, stable = -1, 0
        while time.time() < deadline:
            if pdf.is_file():
                size = pdf.stat().st_size
                if size > 10_000 and size == last_size:
                    stable += 1
                    if stable >= 4:
                        break
                else:
                    stable = 0
                last_size = size
            time.sleep(0.5)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        returncode = proc.returncode
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    if not pdf.is_file() or pdf.stat().st_size < 10_000:
        raise SystemExit(
            f"PDF 导出失败（exit={returncode}）：{pdf}\n"
            "本机若持续零产出，改用 PowerShell 的 Start-Process -Wait -NoNewWindow 调同一个 Edge 命令。"
        )
    print(f"来源：{source}")
    print(f"浏览器：{find_edge()}")
    print(f"输出：{pdf} · {pdf.stat().st_size} 字节 · {count_pages(pdf)} 页")


if __name__ == "__main__":
    main()
