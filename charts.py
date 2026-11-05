"""Draw the article's data charts straight from out/, with the numbers asserted against the text.

  python charts.py [--out ../publish2/images]      (needs matplotlib; the tool itself does not)
"""

import argparse
import json
from datetime import date, timedelta
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "Noto Sans CJK SC", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False
INK, MUTED, BLUE, RED = "#1f2328", "#8b949e", "#6e8fb5", "#d1242f"


def timeline(out: Path) -> None:
    data = json.loads((BASE / "out" / "replay.json").read_text(encoding="utf-8"))
    s, days = data["summary"], data["days"]
    assert (s["baseline_alerts"], s["baseline_alert_days"]) == (79, 12)
    assert (s["first_day_red_items"], s["later_message_days"]) == (12, 1)
    alert_days = [(date.fromisoformat(d["date"]), d["baseline_alerts"]) for d in days if d["baseline_alerts"]]
    msg_days = [(date.fromisoformat(d["date"]), d["red_items"]) for d in days if d["sentinel_messages"]]
    assert sum(n for _, n in alert_days) == 79 and len(msg_days) == 2

    fig, (top, bot) = plt.subplots(2, 1, figsize=(10, 4.6), dpi=120, sharex=True,
                                   gridspec_kw={"height_ratios": [3, 1.1], "hspace": 0.08})
    top.bar([d for d, _ in alert_days], [n for _, n in alert_days], width=3, color=BLUE)
    for i, (d, n) in enumerate(alert_days):
        near = i + 1 < len(alert_days) and (alert_days[i + 1][0] - d).days < 8
        top.text(d, n + 0.6, str(n), ha="right" if near else "center", va="bottom", fontsize=10, color=INK)
    top.set_ylim(0, max(n for _, n in alert_days) * 1.25)
    top.set_ylabel("漏洞库新提醒（条）", fontsize=11, color=INK)
    top.set_title(f"漏洞库：{s['baseline_alerts']} 条，分布在 {s['baseline_alert_days']} 天", loc="left",
                  fontsize=12, color=INK)

    for d, items in msg_days:
        bot.scatter([d], [0], s=140, color=RED, zorder=3)
        label = f"首次体检 {len(items)} 件" if d == date.fromisoformat(s["start"]) else \
            f"{d.month} 月 {d.day} 日 fastjson 新漏洞"
        assert d == date.fromisoformat(s["start"]) or items == ["legacy-order:CVE-2025-70974"]
        first = d == date.fromisoformat(s["start"])
        bot.annotate(label, (d, 0), xytext=(14, 22 if first else -22), textcoords="offset points",
                     va="center", fontsize=11, color=RED,
                     arrowprops={"arrowstyle": "-", "color": RED, "lw": 0.8})
    bot.set_ylim(-1.6, 1.6)
    bot.set_yticks([])
    bot.set_ylabel("@ 负责人", fontsize=11, color=INK, rotation=0, ha="right", va="center")
    bot.xaxis.set_major_locator(mdates.MonthLocator())
    bot.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{mdates.num2date(x).month} 月"))
    bot.set_xlim(date.fromisoformat(s["start"]) - timedelta(days=6), date.fromisoformat(s["end"]) + timedelta(days=3))
    for ax in (top, bot):
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        ax.tick_params(colors=MUTED, labelsize=10)
    bot.spines["left"].set_visible(False)
    fig.savefig(out / "fig01-replay-timeline.png", bbox_inches="tight", facecolor="white")


def ablation(out: Path) -> None:
    rows = []
    for mode, label in (("osv", "只看漏洞库"), ("static", "只用规则"), ("full", "规则 + 大模型 + 元宝")):
        d = json.loads((BASE / "out" / "eval" / mode / "summary.json").read_text(encoding="utf-8"))
        sc = d["scenarios"]
        reds = sum(x["levels"]["red"] for x in sc)
        rows.append((label, sum(x["pass"] for x in sc), len(sc), reds, sum(x["alerts"] for x in sc)))
    assert [(p, r) for _, p, _, r, _ in rows] == [(5, 50), (11, 8), (15, 14)]
    assert all(n == 15 and a == 120 for _, _, n, _, a in rows)

    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), dpi=120, gridspec_kw={"wspace": 0.35})
    colors = ["#c9d1d9", BLUE, RED]
    for ax, idx, title, top in ((axes[0], 1, "场景通过（共 15 个）", 15), (axes[1], 3, "标成“今天修”（共 120 条）", 50)):
        vals = [r[idx] for r in rows]
        ax.barh([r[0] for r in rows], vals, color=colors, height=0.55)
        for i, v in enumerate(vals):
            ax.text(v + top * 0.02, i, str(v), va="center", fontsize=12, color=INK)
        ax.set_xlim(0, top * 1.15)
        ax.invert_yaxis()
        ax.set_title(title, loc="left", fontsize=12, color=INK)
        ax.set_xticks([])
        for side in ("top", "right", "bottom"):
            ax.spines[side].set_visible(False)
        ax.tick_params(colors=INK, labelsize=11, length=0)
    axes[1].set_yticklabels([])
    fig.savefig(out / "fig07-ablation.png", bbox_inches="tight", facecolor="white")


def sandbox(out: Path) -> None:
    """Fig 5 right: for each fix, the attack result before vs after the upgrade, plus the smoke test."""
    data = json.loads((BASE / "out" / "verify.json").read_text(encoding="utf-8"))
    assert all(r["attack_before"] == "EXPLOITED" and r["attack_after"] == "BLOCKED"
               and r["test_after"] == "pass" for r in data)
    labels = [f"{r['package']} {r['vulnerable_version']}→{r['fixed_version']}\n{r['cve']}" for r in data]
    n = len(data)
    fig, ax = plt.subplots(figsize=(9, 1.0 + 0.95 * n), dpi=120)
    y = range(n)
    for i, r in enumerate(data):
        # 升级前：攻击打通（红）；升级后：攻击被挡 + 测试通过（蓝）
        ax.barh(i + 0.18, 1, height=0.33, color=RED, zorder=2)
        ax.barh(i - 0.18, 1, height=0.33, color=BLUE, zorder=2)
        ax.text(0.02, i + 0.18, "升级前：攻击打通 EXPLOITED", va="center", ha="left", fontsize=11, color="white")
        ax.text(0.02, i - 0.18, f"升级后：攻击被挡 BLOCKED ·自带测试 pass ·{r['backend']}",
                va="center", ha="left", fontsize=10.5, color="white")
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=11, color=INK)
    ax.set_xlim(0, 1)
    ax.set_xticks([])
    ax.invert_yaxis()
    ax.set_title("沙箱预演：同一攻击，升级前后各打一次", loc="left", fontsize=12, color=INK)
    for side in ("top", "right", "bottom", "left"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0)
    fig.savefig(out / "fig05-sandbox-chart.png", bbox_inches="tight", facecolor="white")


def scanners(out: Path) -> None:
    """Fig 6: what each scanner reported vs what it missed, and how much of each is today's fix."""
    rows = []
    for tool, label in (("trivy", "Trivy 0.58.1"), ("grype", "Grype 0.121.1")):
        s = json.loads((BASE / "out" / "triage" / f"{tool}.triage.json").read_text(encoding="utf-8"))["summary"]
        rep, ext = s["levels"], s["extra_levels"]
        rows.append((f"{label}" + chr(10) + "报告", sum(rep.values()), rep["red"]))
        rows.append((f"{label}" + chr(10) + "漏报、自己认出", sum(ext.values()), ext["red"]))
    assert [(n, r) for _, n, r in rows] == [(98, 8), (24, 6), (106, 12), (14, 2)]
    assert rows[0][2] + rows[1][2] == rows[2][2] + rows[3][2] == 14

    fig, ax = plt.subplots(figsize=(10, 3.6), dpi=120)
    for i, (label, n, red) in enumerate(rows):
        ax.barh(i, red, color=RED, height=0.6)
        ax.barh(i, n - red, left=red, color="#c9d1d9", height=0.6)
        ax.text(n + 1.5, i, f"{n} 条，今天修 {red}", va="center", fontsize=11, color=INK)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r[0] for r in rows], fontsize=11, color=INK)
    ax.invert_yaxis()
    ax.set_xlim(0, 135)
    ax.set_xticks([])
    ax.set_title("两个扫描器各自合计都是 14 条今天修", loc="left", fontsize=12, color=INK)
    for side in ("top", "right", "bottom"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0)
    fig.savefig(out / "fig06-scanners.png", bbox_inches="tight", facecolor="white")


def gates(out: Path) -> None:
    """Fig 2: the gates every alert passes; counts come from the full-mode eval and the sandbox run."""
    import glob, subprocess, shutil
    rows = [r for f in glob.glob(str(BASE / "out" / "eval" / "full" / "s*.json"))
            for r in json.loads(Path(f).read_text(encoding="utf-8")).get("rows", [])]
    total, mal = len(rows), sum(r["malware"] for r in rows)
    reach = [r for r in rows if not r["malware"] and r.get("reachable") == "yes"]
    hot = [r for r in reach if r["level"] == "red"]
    red = sum(r["level"] == "red" for r in rows)
    proven = sum(r["fix_proven"] for r in json.loads((BASE / "out" / "verify.json").read_text(encoding="utf-8")))
    assert (total, mal, len(reach), len(hot), red, proven) == (120, 2, 18, 12, 14, 2) and red == len(hot) + mal
    main = [("漏洞库对上版本", f"{total} 条"), ("代码真调用、外人能控制？", f"{total - mal} 条，大模型 3 票、给行号"),
            ("有人在利用吗？", f"{len(reach)} 条，KEV、EPSS、两站证据"), ("今天修", f"{red} 条"),
            ("能在沙箱里真打一次吗？", "升级前打通、升级后挡住")]
    exits = [f"{mal} 条恶意包 → 直接今天修", f"{total - mal - len(reach)} 条 → 本周修或只记录",
             f"{len(reach) - len(hot)} 条 → 本周修", "",
             f"{proven} 条 → 生成补丁；其余 {red - proven} 条给升级建议"]
    W, bh, gap = 760, 56, 34
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{40 + 5 * (bh + gap)}" '
           f'font-family="Microsoft YaHei" ><rect width="100%" height="100%" fill="#fff"/>']
    for i, ((title, sub), ex) in enumerate(zip(main, exits)):
        y = 20 + i * (bh + gap)
        fill, stroke = ("#FCEBEB", "#A32D2D") if title == "今天修" else ("#F1EFE8", "#5F5E5A")
        svg += [f'<rect x="40" y="{y}" width="300" height="{bh}" rx="4" fill="{fill}" stroke="{stroke}" stroke-width="0.8"/>',
                f'<text x="190" y="{y + 22}" font-size="15" text-anchor="middle" fill="#2C2C2A">{title}</text>',
                f'<text x="190" y="{y + 42}" font-size="12.5" text-anchor="middle" fill="#5F5E5A">{sub}</text>',
                ]
        if ex:
            svg += [f'<line x1="340" y1="{y + bh / 2}" x2="408" y2="{y + bh / 2}" stroke="#5F5E5A" stroke-width="1"/>',
                    f'<path d="M402 {y + bh / 2 - 4} L408 {y + bh / 2} L402 {y + bh / 2 + 4}" fill="none" stroke="#5F5E5A"/>',
                    f'<text x="416" y="{y + bh / 2 + 5}" font-size="13.5" '
                    f'fill="{"#A32D2D" if "今天修" in ex or "补丁" in ex else "#444441"}">{ex}</text>']
        if i < 4:
            svg += [f'<line x1="190" y1="{y + bh}" x2="190" y2="{y + bh + gap - 2}" stroke="#5F5E5A" stroke-width="1"/>',
                    f'<path d="M186 {y + bh + gap - 8} L190 {y + bh + gap - 2} L194 {y + bh + gap - 8}" fill="none" stroke="#5F5E5A"/>']
    svg.append("</svg>")
    html = out / "fig02-gates.html"
    html.write_text('<html><body style="margin:0">' + "".join(svg) + "</body></html>", encoding="utf-8")
    import tempfile
    browser = shutil.which("chrome") or r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    profile = tempfile.mkdtemp(prefix="charts-chrome-")
    subprocess.run([browser, "--headless=new", "--disable-gpu", "--user-data-dir=" + profile, "--force-device-scale-factor=2", "--hide-scrollbars",
                    f"--window-size={W},{40 + 5 * (bh + gap) - 20}", f"--screenshot={out / 'fig02-gates.png'}",
                    html.resolve().as_uri()], check=True, capture_output=True, timeout=60)
    if not (out / "fig02-gates.png").exists():
        raise SystemExit("fig02-gates.png 没有生成，HTML 留在 " + str(html))
    html.unlink()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(BASE.parent / "publish2" / "images"))
    out = Path(ap.parse_args().out)
    out.mkdir(parents=True, exist_ok=True)
    timeline(out)
    ablation(out)
    sandbox(out)
    scanners(out)
    gates(out)
    print("written to", out)
