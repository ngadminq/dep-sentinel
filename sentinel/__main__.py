"""dep-sentinel CLI.

  python -m sentinel patrol ROOT [ROOT ...] [--send]   自动发现 ROOT 下所有项目，只推送和上次相比的变化
  python -m sentinel scan  REPO [REPO ...] [--mode full|static|osv] [--send] [--out DIR]
  python -m sentinel ask   "群里转来的文字或问题" --repos REPO [REPO ...]
  python -m sentinel fix   REPO [REPO ...] [--out DIR]   沙箱里预演修复，证明有效后生成补丁
  python -m sentinel triage REPORT.json --root DIR [--out DIR]   读 Trivy / Grype 报告，挑出今天要修的
"""

import argparse
import json
import sys
import time
from pathlib import Path

from . import cache, output, pipeline


def _scan(args) -> None:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for path in args.repos:
        result = pipeline.scan(Path(path), args.mode)
        rows = [output.finding_row(f) for f in result["findings"]]
        msg = output.dingtalk_markdown(result)
        name = result["repo"].name
        (out / f"{name}.findings.json").write_text(json.dumps(
            {"repo": name, "mode": args.mode, "llm": result["llm"], "stats": result["stats"], "findings": rows},
            ensure_ascii=False, indent=1), encoding="utf-8")
        (out / f"{name}.vex.json").write_text(json.dumps(output.openvex(result), ensure_ascii=False, indent=1),
                                              encoding="utf-8")
        print(msg["markdown"]["text"], "\n")
        if args.send:
            print("钉钉:", output.send_dingtalk(msg))
    print("调用统计:", json.dumps(cache.STATS, ensure_ascii=False), file=sys.stderr)


def _patrol(args) -> None:
    from . import monitor
    report = monitor.patrol([Path(r) for r in args.roots], args.mode)
    msg = monitor.daily_message(report)
    kinds = {}
    for e in report["events"]:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"项目 {len(report['projects'])} 个，变化 {kinds}，已修复 {len(report['resolved'])}")
    if msg is None:
        print("今天没有新的需要处理的问题，不发消息。")
        return
    print(msg["markdown"]["text"])
    if args.send:
        print("钉钉:", output.send_dingtalk(msg))


def _ask(args) -> None:
    res = pipeline.ask(args.question, [Path(p) for p in args.repos], args.mode)
    parsed = res["parsed"]
    print(f"识别：组件 {[c['name'] for c in parsed['components']]}，编号 {parsed['cves']}")
    if not res["hits"] and not res["used"]:
        print("✅ 没有事：所有仓库都没有使用相关组件。")
        return
    repos = {}
    for repo, f in res["hits"]:
        repos.setdefault(repo.name, (repo, []))[1].append(output.finding_row(f))
    for name, (repo, rows) in repos.items():
        top = min(rows, key=lambda r: ["red", "yellow", "white"].index(r["level"]))
        print(f"{output.ICON[top['level']]}  {name}（负责人 {repo.owner.get('name')}）：{top['package']} "
              f"{', '.join(sorted({c for r in rows for c in r['cves']}))} —— {top['reason']}")
    for repo, pkg in res["used"]:
        if repo.name not in repos:
            print(f"🟢  {repo.name}：在用 {pkg.name}@{pkg.version}，但该版本不在漏洞库受影响范围")


def _fix(args) -> None:
    from . import fix, sandbox
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report = ["# 依赖修复预演报告", ""]
    proven = attempted = 0
    for path in args.repos:
        repo_path = Path(path)
        result = pipeline.scan(repo_path, args.mode)
        repo = result["repo"]
        spec = sandbox.load_spec(repo_path)
        # 候选 = 今天必须修的（red），以及“在用且可达、且带有可复现攻击脚本”的（yellow）
        def matches_spec(row):
            return spec and spec.get("cve") in {*row["cves"], row["vuln"]}
        rows = [output.finding_row(f) for f in result["findings"]]
        targets = [r for r in rows if r["level"] == "red"
                   or (r["reachable"] == "yes" and matches_spec(r))]
        report += [f"## {repo.name}", ""]
        if not targets:
            report += ["没有今天必须修的漏洞。", ""]
            print(f"{repo.name}: 无待修项")
            continue
        for row in targets:
            attempted += 1
            cve = row["cves"][0] if row["cves"] else row["vuln"]
            eco, rest = row["package"].split("/", 1)
            name, cur = rest.rsplit("@", 1)
            fixed = row["fixed"]
            report += [f"### {row['package']} — {cve}",
                       f"- 判定：{output.ICON[row['level']]}（{row['reason']}）",
                       f"- 调用位置：{', '.join(row['reach_evidence'][:3]) or '—'}"]
            rehearsal = None
            if matches_spec(row):
                rehearsal = sandbox.rehearse(repo_path, spec)
                fixed = rehearsal["fixed_version"]
                escalate = "；沙箱已证实可被利用，按今天必须修处理" if (
                    row["level"] != "red" and rehearsal["attack_before"] == "EXPLOITED") else ""
                report += [f"- 沙箱预演（{rehearsal['backend']}，{rehearsal['seconds']}s）："
                           f"攻击前 **{rehearsal['attack_before']}** → 升级 {rehearsal['fixed_version']} 后 "
                           f"**{rehearsal['attack_after']}**；项目自带测试 **{rehearsal['test_after']}**{escalate}"]
            else:
                report.append("- 沙箱预演：本例无可复现的攻击脚本，仅做版本升级")
            if not fixed:
                report += ["- ⚠️ 暂无修复版本，需人工处理", ""]
                print(f"{repo.name} {name}: 无修复版本")
                continue
            if rehearsal and not rehearsal["fix_proven"]:
                report += ["- ⚠️ 沙箱未能证明修复有效（升级后攻击仍成功或测试不过），不自动提交，转人工", ""]
                print(f"{repo.name} {name}: 预演未通过，转人工")
                continue
            patch = fix.make_patch(repo_path, eco, name, fixed)
            if not patch["ok"]:
                report += [f"- ⚠️ 无法自动生成补丁：{patch['why']}", ""]
                print(f"{repo.name} {name}: {patch['why']}")
                continue
            pfile = out / f"{repo.name}.{name.replace('/', '_').replace(':', '_')}.patch"
            pfile.write_text(patch["patch"], encoding="utf-8", newline="\n")
            proven += 1
            report += [f"- 修复：{name} {cur} → {fixed}",
                       f"- 建议分支：`{fix.branch_name(repo.name, cve, name)}`",
                       f"- 补丁：`{pfile.name}`（`git apply` 可直接合入）", ""]
            print(f"{repo.name} {name}: 预演通过，补丁已生成 -> {pfile.name}")
    report += ["---", f"共 {attempted} 条需今天修，其中 {proven} 条已在沙箱证明修复有效并生成补丁。"]
    (out / "fix-report.md").write_text("\n".join(report), encoding="utf-8")
    print(f"\n报告：{out / 'fix-report.md'}")
    print("调用统计:", json.dumps(cache.STATS, ensure_ascii=False), file=sys.stderr)


def _triage(args) -> None:
    from . import scanners
    from .discover import find_projects
    root, out = Path(args.root), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tool, entries = scanners.load(Path(args.report))
    groups = scanners.by_project(entries, find_projects(root), root)
    pairs = {(e["ecosystem"], scanners.norm(e["ecosystem"], e["name"]), e["version"], i)
             for e in entries for i in sorted(e["ids"])[:1]}
    levels, extra, statements, projects, unmatched = {"red": 0, "yellow": 0, "white": 0},         {"red": 0, "yellow": 0, "white": 0}, [], [], []
    for proj in find_projects(root):
        ents = groups.get(proj, [])
        result = pipeline.scan(proj, args.mode, scanner=ents)
        rows = []
        for f in result["findings"]:
            r = output.finding_row(f) | {"by_scanner": f["by_scanner"]}
            (levels if f["by_scanner"] else extra)[r["level"]] += 1
            rows.append(r)
        doc = output.openvex(result)
        statements += doc["statements"]
        (out / "vex").mkdir(exist_ok=True)
        (out / "vex" / f"{result['repo'].name}.vex.json").write_text(
            json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        unmatched += [dict(u, project=result["repo"].name) for u in result["scanner_unmatched"]]
        levels["yellow"] += len(result["scanner_unmatched"])     # no OSV record to reason about: a person looks
        projects.append({"project": result["repo"].name, "scanner_entries": len(ents), "findings": rows,
                         "message": output.dingtalk_markdown(result)["markdown"]["text"]})
        mine = [r for r in rows if r["by_scanner"]]
        extra_red = sum(r["level"] == "red" for r in rows if not r["by_scanner"])
        print(f"{result['repo'].name:<15} {tool} 报 {len(ents):>2} 条 → 今天修 {sum(r['level'] == 'red' for r in mine)}"
              f" ｜ 漏报补上 {len(rows) - len(mine)} 条，今天修 {extra_red}")
    # OpenVEX names products by package purl, not by project: one project's "not_affected" would hide the
    # same package+CVE in every other project. The merged file keeps a not_affected only when no project disagrees.
    def _key(st):
        return st["vulnerability"]["name"], st["products"][0]["@id"]
    disputed = {_key(st) for st in statements if st["status"] != "not_affected"}
    dropped = [st for st in statements if st["status"] == "not_affected" and _key(st) in disputed]
    statements = [st for st in statements if st not in dropped]
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"urn:dep-sentinel:triage:{tool}",
           "author": "dep-sentinel", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "version": 1, "statements": statements}
    summary = {"tool": tool, "report_entries": len(entries), "projects": len(projects),
               "levels": levels, "extra_levels": extra, "vex_not_affected": sum(s["status"] == "not_affected" for s in statements),
               "vex_dropped_conflicts": len(dropped),
               "unmatched": unmatched}
    (out / f"{tool}.vex.json").write_text(json.dumps(vex, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / f"{tool}.triage.json").write_text(json.dumps({"summary": summary, "projects": projects},
                                                        ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "unmatched"}, ensure_ascii=False))
    print(f"漏洞库对不上的扫描器条目 {len(unmatched)} 条（按本周修处理，见 {tool}.triage.json）")
    print("调用统计:", json.dumps(cache.STATS, ensure_ascii=False), file=sys.stderr)
    if args.fail_on_red and levels["red"] + extra["red"]:
        sys.exit(1)     # CI: break the build only when something has to be fixed today


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("repos", nargs="+")
    s.add_argument("--mode", default="full", choices=["full", "static", "osv"])
    s.add_argument("--send", action="store_true")
    s.add_argument("--out", default="out")
    s.set_defaults(fn=_scan)
    pt = sub.add_parser("patrol")
    pt.add_argument("roots", nargs="+")
    pt.add_argument("--mode", default="full", choices=["full", "static"])
    pt.add_argument("--send", action="store_true")
    pt.set_defaults(fn=_patrol)
    a = sub.add_parser("ask")
    a.add_argument("question")
    a.add_argument("--repos", nargs="+", required=True)
    a.add_argument("--mode", default="full", choices=["full", "static"])
    a.set_defaults(fn=_ask)
    fx = sub.add_parser("fix")
    fx.add_argument("repos", nargs="+")
    fx.add_argument("--mode", default="full", choices=["full", "static", "osv"])
    fx.add_argument("--out", default="out/fixes")
    fx.set_defaults(fn=_fix)
    tr = sub.add_parser("triage")
    tr.add_argument("report")
    tr.add_argument("--root", required=True)
    tr.add_argument("--mode", default="full", choices=["full", "static", "osv"])
    tr.add_argument("--out", default="out/triage")
    tr.add_argument("--fail-on-red", action="store_true", help="有今天修的条目时以 1 退出，给 CI 用")
    tr.set_defaults(fn=_triage)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
