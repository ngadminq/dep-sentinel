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
    """Fig 1: one time axis; bars = alerts the vulnerability database added that day, red dots = days we @ someone."""
    data = json.loads((BASE / "out" / "replay.json").read_text(encoding="utf-8"))
    s, days = data["summary"], data["days"]
    assert (s["baseline_alerts"], s["baseline_alert_days"]) == (79, 12)
    assert (s["first_day_red_items"], s["later_message_days"]) == (12, 1)
    alert_days = [(date.fromisoformat(d["date"]), d["baseline_alerts"]) for d in days if d["baseline_alerts"]]
    msg_days = [(date.fromisoformat(d["date"]), d["red_items"]) for d in days if d["sentinel_messages"]]
    assert sum(n for _, n in alert_days) == 79 and len(msg_days) == 2
    start, end = date.fromisoformat(s["start"]), date.fromisoformat(s["end"])

    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=120)
    ax.bar([d for d, _ in alert_days], [n for _, n in alert_days], width=3, color=BLUE, label="漏洞库当天新增的告警")
    for i, (d, n) in enumerate(alert_days):
        near = i + 1 < len(alert_days) and (alert_days[i + 1][0] - d).days < 8
        ax.text(d, n + 0.6, str(n), ha="right" if near else "center", va="bottom", fontsize=10, color=INK)
    top = max(n for _, n in alert_days) * 1.35
    for d, items in msg_days:
        first = d == start
        assert first or items == ["legacy-order:CVE-2025-70974"]
        ax.axvline(d, color=RED, lw=1.4, ls="--", zorder=1, label="需要 @ 负责人的日子" if first else None)
        ax.annotate(f"首次体检：{len(items)} 件今天修" if first else f"{d.month} 月 {d.day} 日：fastjson 新漏洞",
                    (d, top * (0.95 if first else 0.84)), xytext=(30 if first else 8, 0), textcoords="offset points",
                    va="center", fontsize=11, color=RED)
    ax.set_ylim(0, top)
    ax.set_ylabel("新增告警（条）", fontsize=11, color=INK)
    ax.xaxis.set_major_locator(mdates.MonthLocator())
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{mdates.num2date(x).month} 月"))
    ax.set_xlim(start - timedelta(days=6), end + timedelta(days=3))
    ax.set_xlabel("2026 年（每天检查一次）", fontsize=11, color=INK)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(colors=MUTED, labelsize=10)
    ax.legend(loc="center right", frameon=False, fontsize=10)
    fig.savefig(out / "fig01-replay-timeline.png", bbox_inches="tight", facecolor="white")


def vuln_types(out: Path) -> None:
    """Fig 1b: what the 120 alerts are (type x severity), and how many of each type are today's fix."""
    import collections, glob, os
    os.environ.setdefault("SENTINEL_OFFLINE", "1")
    from sentinel import intel
    from sentinel.vulntype import vuln_type
    rows = [r for f in glob.glob(str(BASE / "out" / "eval" / "full" / "s*.json"))
            for r in json.loads(Path(f).read_text(encoding="utf-8")).get("rows", [])]
    by = collections.defaultdict(collections.Counter)
    for r in rows:
        v = intel.osv_vuln(r["vuln"])
        t = vuln_type((v.get("database_specific") or {}).get("cwe_ids"), r["malware"])
        by[t][r["severity"] or "未评级"] += 1
        by[t]["今天修"] += r["level"] == "red"
    assert sum(sum(c[k] for k in c if k != "今天修") for c in by.values()) == len(rows) == 120
    assert sum(c["今天修"] for c in by.values()) == 14
    order = sorted(by, key=lambda t: -sum(by[t][k] for k in by[t] if k != "今天修"))
    sevs = [("CRITICAL", "严重", "#8b1a1a"), ("HIGH", "高", RED), ("MODERATE", "中", "#e8a33d"),
            ("LOW", "低", "#c9d1d9"), ("未评级", "未评级", "#eeeeee")]
    fig, ax = plt.subplots(figsize=(10, 4.6), dpi=120)
    for i, t in enumerate(order):
        left = 0
        for key, label, color in sevs:
            n = by[t][key]
            if n:
                ax.barh(i, n, left=left, color=color, height=0.62, label=label if i == 0 or label not in
                        [h.get_label() for h in ax.patches[:-1]] else None)
                left += n
        ax.text(left + 0.6, i, f"{left} 条，今天修 {by[t]['今天修']}", va="center", fontsize=10.5, color=INK)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, _, c in sevs[:4]]
    ax.legend(handles, [l for _, l, _ in sevs[:4]], title="漏洞库评级", loc="lower right", frameon=False, fontsize=10)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels(order, fontsize=11, color=INK)
    ax.invert_yaxis()
    ax.set_xlim(0, 52)
    ax.set_xlabel("告警条数", fontsize=11, color=INK)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(colors=MUTED, labelsize=10, length=0)
    fig.savefig(out / "fig01b-vuln-types.png", bbox_inches="tight", facecolor="white")


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


def _shoot(html_text: str, dest: Path, width: int, height: int) -> None:
    """Render an HTML snippet with headless Chrome at 2x."""
    import shutil, subprocess, tempfile
    tmp = Path(tempfile.mkdtemp(prefix="charts-"))
    (tmp / "p.html").write_text(html_text, encoding="utf-8")
    browser = shutil.which("chrome") or r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                    f"--user-data-dir={tmp / 'profile'}", f"--window-size={width},{height}", f"--screenshot={dest}",
                    (tmp / "p.html").as_uri()], check=True, capture_output=True, timeout=60)
    assert dest.exists(), dest


def gates(out: Path) -> None:
    """Fig 2: the gates every alert passes, with the exploitation signals drawn as icons.
    Counts come from the full-mode eval and the sandbox run."""
    import glob
    rows = [r for f in glob.glob(str(BASE / "out" / "eval" / "full" / "s*.json"))
            for r in json.loads(Path(f).read_text(encoding="utf-8")).get("rows", [])]
    total, mal = len(rows), sum(r["malware"] for r in rows)
    reach = [r for r in rows if not r["malware"] and r.get("reachable") == "yes"]
    hot = [r for r in reach if r["level"] == "red"]
    red = sum(r["level"] == "red" for r in rows)
    proven = sum(r["fix_proven"] for r in json.loads((BASE / "out" / "verify.json").read_text(encoding="utf-8")))
    assert (total, mal, len(reach), len(hot), red, proven) == (120, 2, 18, 12, 14, 2) and red == len(hot) + mal

    def step(icon, title, sub, exit_icon, exit_text, hot_exit=False, today=False):
        box = "today" if today else ""
        ex = (f'<div class="arrow">→</div><div class="exit {"hot" if hot_exit else ""}">'
              f'<span class="i">{exit_icon}</span>{exit_text}</div>') if exit_text else ""
        return (f'<div class="row"><div class="box {box}"><span class="bi">{icon}</span>'
                f'<div><div class="ti">{title}</div><div class="su">{sub}</div></div></div>{ex}</div>')

    signals = ('<div class="sig"><span>🛡️ 进了官方“已被利用”清单</span><span>🔥 被利用概率 ≥ 10%</span>'
               '<span>🌐 两个网站有攻击代码</span></div>')
    body = "".join([
        step("📋", "漏洞库对上版本", f"{total} 条告警", "☠️", f"{mal} 条恶意包，直接今天修", hot_exit=True),
        '<div class="down">↓</div>',
        step("🔍", "代码真调用、外人能控制？", "大模型判 3 次，必须给出行号", "💤",
             f"{total - mal - len(reach)} 条打不到或没调用 → 本周修、只记录"),
        '<div class="down">↓ ' + f"{len(reach)} 条能打到</div>",
        step("📡", "有人在利用吗？", "三个信号满足一个就算", "⏳", f"{len(reach) - len(hot)} 条暂无信号 → 本周修"),
        signals,
        '<div class="down">↓ ' + f"{len(hot)} 条 + {mal} 条恶意包</div>",
        step("🚨", f"今天修 {red} 条", "@ 负责人", "", "", today=True),
        '<div class="down">↓</div>',
        step("🧪", "沙箱里真打一次", "升级前打通、升级后挡住、测试通过", "🩹",
             f"{proven} 条生成补丁；其余 {red - proven} 条给升级建议", hot_exit=True),
    ])
    page = f"""<html><head><meta charset="utf-8"><style>
body {{ margin:0; background:#fff; font-family:"Microsoft YaHei",sans-serif; color:#2c2c2a; }}
.wrap {{ padding:22px 26px; width:760px; box-sizing:border-box; }}
.row {{ display:flex; align-items:center; }}
.box {{ width:330px; display:flex; align-items:center; gap:12px; border:1px solid #5f5e5a; border-radius:6px;
        padding:10px 14px; background:#f5f4ef; box-sizing:border-box; }}
.box.today {{ background:#fcebeb; border-color:#a32d2d; }}
.bi {{ font-size:26px; }}
.ti {{ font-size:16px; font-weight:600; }}
.su {{ font-size:12.5px; color:#5f5e5a; margin-top:2px; }}
.arrow {{ width:48px; text-align:center; font-size:20px; color:#5f5e5a; }}
.exit {{ font-size:14px; color:#444441; display:flex; align-items:center; gap:6px; }}
.exit.hot {{ color:#a32d2d; font-weight:600; }}
.exit .i {{ font-size:20px; }}
.down {{ width:330px; text-align:center; font-size:13px; color:#5f5e5a; margin:6px 0; }}
.sig {{ width:330px; display:flex; flex-direction:column; gap:4px; margin:8px 0 0; padding:8px 14px;
        border:1px dashed #b4b2a9; border-radius:6px; font-size:13px; box-sizing:border-box; }}
</style></head><body><div class="wrap">{body}</div></body></html>"""
    _shoot(page, out / "fig02-gates.png", 760, 560)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(BASE.parent / "publish2" / "images"))
    out = Path(ap.parse_args().out)
    out.mkdir(parents=True, exist_ok=True)
    timeline(out)
    vuln_types(out)
    ablation(out)
    sandbox(out)
    scanners(out)
    gates(out)
    print("written to", out)
