"""Replay "patrol every day" from START to END with the code frozen as it is today.

A vulnerability becomes visible on its OSV `published` date; KEV counts from its `dateAdded`.
Compared per day:
  baseline   every newly visible vulnerability is one alert (what a version-match scanner sends)
  sentinel   only findings that turn red that day reach a person
Caveat (written into the output): EPSS and web evidence are today's values, not that day's.

  python replay.py [--start 2026-01-01] [--end 2026-11-02] [--mode full]
"""

import argparse
import copy
import json
import sys
from datetime import date, timedelta
from pathlib import Path

from sentinel import gate, intel, pipeline
from sentinel.discover import find_projects

BASE = Path(__file__).resolve().parent
EXCLUDE = {"s10-injection"}      # same code as s04; its poisoned search page only exists inside eval.py


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="2026-01-01")
    ap.add_argument("--end", default="2026-11-02")
    ap.add_argument("--mode", default="full")
    ap.add_argument("--out", default=str(BASE / "out" / "replay.json"))
    args = ap.parse_args()

    kev = intel.kev()
    findings = []
    for path in find_projects(BASE / "scenarios"):
        if path.name in EXCLUDE:
            continue
        res = pipeline.scan(path, args.mode)
        for f in res["findings"]:
            findings.append((res["repo"].name, f))

    start, end = date.fromisoformat(args.start), date.fromisoformat(args.end)
    days, prev_level = [], {}
    d = start
    while d <= end:
        iso = d.isoformat()
        alerts, reds, red_items = 0, set(), []
        for project, f in findings:
            v = f["vuln"]
            pub = (v.get("published") or "")[:10]
            if not pub or pub > iso:
                continue
            key = (project, f["package"].name, v["id"])
            if pub == iso:
                alerts += 1
            day_v = copy.copy(v)
            day_v["kev"] = any(c in kev and kev[c]["dateAdded"] <= iso for c in v["cves"])
            level = gate.decide(f | {"vuln": day_v})["level"]
            if level == "red" and prev_level.get(key) != "red":
                reds.add(project)
                red_items.append(f"{project}:{(v['cves'] or [v['id']])[0]}")
            prev_level[key] = level
        days.append({"date": iso, "baseline_alerts": alerts, "sentinel_messages": len(reds),
                     "red_items": red_items})
        d += timedelta(days=1)

    total_alerts = sum(x["baseline_alerts"] for x in days)
    msg_days = [x for x in days if x["sentinel_messages"]]
    alert_days = [x for x in days if x["baseline_alerts"]]
    before = sum(1 for _, f in findings if (f["vuln"].get("published") or "")[:10] < args.start)
    summary = {"start": args.start, "end": args.end, "projects": len({p for p, _ in findings}),
               "findings_total": len(findings), "known_before_start": before,
               "baseline_alerts": total_alerts, "baseline_alert_days": len(alert_days),
               "sentinel_red_items": sum(len(x["red_items"]) for x in days),
               "sentinel_message_days": len(msg_days),
               "first_day_red_items": len(days[0]["red_items"]),
               "later_red_items": sum(len(x["red_items"]) for x in days[1:]),
               "later_message_days": sum(1 for x in days[1:] if x["sentinel_messages"]),
               "caveat": "EPSS 与网页证据用的是 2026-11-02 的值，不是当天的值"}
    # day one also carries everything published before START (the first check-up)
    assert summary["baseline_alerts"] + before + sum(
        1 for _, f in findings if (f["vuln"].get("published") or "")[:10] > args.end) <= len(findings)
    Path(args.out).write_text(json.dumps({"summary": summary, "days": days}, ensure_ascii=False, indent=1),
                              encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    for x in msg_days:
        print(x["date"], x["red_items"])
    by_month: dict[str, list[int]] = {}
    for x in days:
        m = by_month.setdefault(x["date"][:7], [0, 0])
        m[0] += x["baseline_alerts"]
        m[1] += 1 if x["sentinel_messages"] and x["date"] != args.start else 0
    print("月份  漏洞库新提醒  需要找人的天数（不含首日体检）")
    for m, (a, s) in by_month.items():
        print(m, a, s)


if __name__ == "__main__":
    main()
