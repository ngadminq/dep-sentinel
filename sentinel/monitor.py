"""Daily patrol: discover every project under the roots, scan, and push only what changed.

State (last level of every project x library x vulnerability) lives in STATE_FILE, so a
library nobody touched still raises an alert the day a new flaw in it is published or
lands on the KEV list.
"""

import json
import os
import time
from pathlib import Path

from . import output, pipeline
from .discover import find_projects
from .intel import vkey

STATE_FILE = Path(os.environ.get("SENTINEL_STATE", Path(os.environ.get("SENTINEL_CACHE", "data/cache")).parent / "state.json"))
RANK = {"white": 0, "yellow": 1, "red": 2}


def _key(project: str, row: dict) -> str:
    return f"{project}|{row['package']}|{row['vuln']}"


def patrol(roots: list[Path], mode: str = "full") -> dict:
    """Scan everything; return per-project results plus the change set against yesterday."""
    old = json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
    first_run = not old
    new_state, events, projects = {}, [], []
    for root in roots:
        for path in find_projects(root):
            result = pipeline.scan(path, mode)
            repo = result["repo"]
            rows = [output.finding_row(f) for f in result["findings"]]
            projects.append({"result": result, "rows": rows})
            for r in rows:
                k = _key(repo.name, r)
                new_state[k] = r["level"]
                before = old.get(k)
                if before is None:
                    kind = "new"
                elif RANK[r["level"]] > RANK[before]:
                    kind = "escalated"
                else:
                    continue
                events.append({"kind": kind, "project": repo.name, "owner": repo.owner, "row": r, "before": before})
            for d in repo.undeclared:
                k = f"{repo.name}|undeclared|{d['ecosystem']}:{d['name']}"
                new_state[k] = "undeclared"
                if k not in old:
                    events.append({"kind": "undeclared", "project": repo.name, "owner": repo.owner, "row": d})
    resolved = [k for k in old if k not in new_state and "|undeclared|" not in k]
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(new_state, ensure_ascii=False, indent=0), encoding="utf-8")
    return {"projects": projects, "events": events, "resolved": resolved, "first_run": first_run}


def daily_message(report: dict) -> dict:
    """One group message per day. Silent days send nothing (returns None)."""
    projects, events = report["projects"], report["events"]
    reds = [e for e in events if e["row"].get("level") == "red" and e["kind"] in ("new", "escalated")]
    new_yellow = [e for e in events if e["row"].get("level") == "yellow" and e["kind"] == "new"]
    undeclared = [e for e in events if e["kind"] == "undeclared"]
    libs = sum(len(p["result"]["repo"].packages) for p in projects)
    if not report["first_run"] and not reds and not report["resolved"] and not undeclared:
        return None
    title = "首次体检" if report["first_run"] else time.strftime("%m-%d 巡检")
    lines = [f"### {'🔴' if reds else '✅'} {title}：{len(reds)} 件需今天处理",
             f"> 自动发现 {len(projects)} 个项目、{libs} 个开源库；"
             f"新增 今天修 {len(reds)} / 本周 {len(new_yellow)} / 已修复 {len(report['resolved'])}", ""]
    by_pkg: dict[tuple, list] = {}
    for e in reds:
        by_pkg.setdefault((e["project"], e["row"]["package"]), []).append(e)
    mobiles = []
    for (project, pkg), items in by_pkg.items():
        owner = items[0]["owner"]
        r = items[0]["row"]
        ids = ", ".join((x["row"]["cves"] or [x["row"]["vuln"]])[0] for x in items)
        tag = "（新升级）" if any(x["kind"] == "escalated" for x in items) else ""
        lines += [f"**{project}** · {pkg}{tag}", f"- {ids}：{r['reason']}",
                  f"- 依据：{'；'.join(r['signals']) or '恶意包'}"]
        if r["reach_evidence"]:
            lines.append(f"- 调用位置：{', '.join(r['reach_evidence'][:2])}")
        # one upgrade that clears every known issue of this library in this project
        fixes = [x["fixed"] for p in projects if p["result"]["repo"].name == project
                 for x in p["rows"] if x["package"] == pkg and x["fixed"]]
        if fixes:
            lines.append(f"- 修复：升级到 {max(fixes, key=vkey)}")
        who = owner.get("mobile") or owner.get("name", "")
        lines += [f"- 负责人：@{who}", ""]
        if owner.get("mobile"):
            mobiles.append(owner["mobile"])
    if undeclared:
        names = sorted({f"{e['row']['name']}（{e['project']}）" for e in undeclared})
        lines.append(f"> 代码里用了、但没写进依赖清单的库：{'、'.join(names[:8])}")
    return {"msgtype": "markdown", "markdown": {"title": title, "text": "\n".join(lines)},
            "at": {"atMobiles": sorted(set(mobiles))}}
