"""Run every scenario under each mode and score it against scenarios/*/expect.json.

  python eval.py                      # modes osv, static, full (full needs LLM_* and YUANBAO_API_KEY or cache)
  python eval.py --modes osv static   # no keys needed
  SENTINEL_OFFLINE=1 python eval.py   # replay recorded calls only
"""

import argparse
import json
import sys
import time
from pathlib import Path

from sentinel import cache, llm, output, pipeline

BASE = Path(__file__).resolve().parent
RANK = {"red": 2, "yellow": 1, "white": 0}


def _match(row: dict, ident: str) -> bool:
    return ident in {*row["cves"], row["vuln"]}


def check(rows: list[dict], exp: dict, repo=None) -> list[dict]:
    """Return one {"check", "ok", "detail"} per expectation."""
    out = []
    have = {f"{p.name}@{p.version}" for p in repo.packages} if repo else set()
    for want in exp.get("has_package", []):
        out.append({"check": f"从代码里找到 {want}", "ok": want in have, "detail": sorted(have)[:6]})
    undeclared = {d["name"] for d in repo.undeclared} if repo else set()
    for want in exp.get("undeclared", []):
        out.append({"check": f"发现未声明的 {want}", "ok": want in undeclared, "detail": sorted(undeclared)})
    for ident in exp.get("red", []):
        got = [r["level"] for r in rows if _match(r, ident)]
        out.append({"check": f"{ident} 必须为 red", "ok": "red" in got, "detail": got})
    if "allow_red_only" in exp:
        fp = [r["cves"][0] if r["cves"] else r["vuln"] for r in rows if r["level"] == "red"
              and not set(exp["allow_red_only"]) & {*r["cves"], r["vuln"]}]
        out.append({"check": "没有多余的 red", "ok": not fp, "detail": fp})
    for name in exp.get("red_package", []):
        got = [r["level"] for r in rows if r["package"].split("/", 1)[1].rsplit("@", 1)[0] == name]
        out.append({"check": f"{name} 必须为 red", "ok": "red" in got, "detail": got})
    for ident, level in exp.get("min_level", {}).items():
        got = [r["level"] for r in rows if _match(r, ident)]
        out.append({"check": f"{ident} 至少 {level}", "ok": any(RANK[g] >= RANK[level] for g in got), "detail": got})
    for ident in exp.get("reachable", []):
        got = [r["reachable"] for r in rows if _match(r, ident)]
        out.append({"check": f"{ident} 判定可达", "ok": "yes" in got, "detail": got})
    for ident in exp.get("not_reachable", []):
        got = [r["reachable"] for r in rows if _match(r, ident)]
        out.append({"check": f"{ident} 判定不可达", "ok": bool(got) and "yes" not in got, "detail": got})
    if "all_level" in exp:
        bad = [r["vuln"] for r in rows if r["level"] != exp["all_level"]]
        out.append({"check": f"全部为 {exp['all_level']}", "ok": not bad, "detail": bad})
    if "max_findings" in exp:
        out.append({"check": f"告警数 ≤ {exp['max_findings']}", "ok": len(rows) <= exp["max_findings"],
                    "detail": len(rows)})
    return out


def run_mode(mode: str, out_dir: Path) -> dict:
    scen = []
    for d in sorted((BASE / "scenarios").glob("s*")):
        exp = json.loads((d / "expect.json").read_text(encoding="utf-8"))
        inject = json.loads((d / "inject.json").read_text(encoding="utf-8")) if (d / "inject.json").exists() else None
        started = time.perf_counter()
        result = pipeline.scan(d, mode, inject)
        rows = [output.finding_row(f) for f in result["findings"]]
        checks = check(rows, exp, result["repo"])
        levels = {k: sum(r["level"] == k for r in rows) for k in RANK}
        scen.append({"id": d.name, "title": exp["title"], "alerts": len(rows), "levels": levels,
                     "checks": checks, "pass": all(c["ok"] for c in checks), "stats": result["stats"],
                     "seconds": round(time.perf_counter() - started, 1)})
        (out_dir / f"{d.name}.json").write_text(json.dumps(
            {"scenario": d.name, "mode": mode, "llm": result["llm"], "rows": rows,
             "message": output.dingtalk_markdown(result)["markdown"]["text"],
             "vex": output.openvex(result)}, ensure_ascii=False, indent=1), encoding="utf-8")
    questions = []
    if mode != "osv":
        repos = sorted((BASE / "scenarios").glob("s*"))
        for q in json.loads((BASE / "scenarios" / "questions.json").read_text(encoding="utf-8")):
            res = pipeline.ask(q["text"], repos, mode)
            got = sorted({repo.name for repo, _ in res["hits"]})
            questions.append({"id": q["id"], "expected": sorted(q["affected"]), "got": got,
                              "pass": got == sorted(q["affected"]), "parsed": res["parsed"]})
    return {"mode": mode, "llm": llm.enabled() and mode == "full", "scenarios": scen, "questions": questions}


def report(results: list[dict]) -> str:
    lines = ["| 场景 | " + " | ".join(f"{r['mode']} red/总 | {r['mode']} 通过" for r in results) + " |",
             "|---|" + "---|---|" * len(results)]
    for i, s in enumerate(results[0]["scenarios"]):
        cells = []
        for r in results:
            x = r["scenarios"][i]
            cells += [f"{x['levels']['red']}/{x['alerts']}", "✅" if x["pass"] else "❌"]
        lines.append(f"| {s['id']} {s['title']} | " + " | ".join(cells) + " |")
    lines.append("")
    for r in results:
        total = sum(s["alerts"] for s in r["scenarios"])
        red = sum(s["levels"]["red"] for s in r["scenarios"])
        passed = sum(s["pass"] for s in r["scenarios"])
        q = f"，问答 {sum(x['pass'] for x in r['questions'])}/{len(r['questions'])}" if r["questions"] else ""
        llm_calls = sum(s["stats"]["llm_calls"] for s in r["scenarios"])
        lines.append(f"- **{r['mode']}**：场景通过 {passed}/{len(r['scenarios'])}，告警 {total} 条中标红 {red} 条"
                     f"{q}，大模型调用 {llm_calls} 次")
    return "\n".join(lines)


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--modes", nargs="+", default=["osv", "static", "full"])
    ap.add_argument("--out", default=str(BASE / "out" / "eval"))
    args = ap.parse_args()
    results = []
    for mode in args.modes:
        out_dir = Path(args.out) / mode
        out_dir.mkdir(parents=True, exist_ok=True)
        if mode == "full" and not llm.enabled():
            print("跳过 full：未设置 LLM_BASE_URL / LLM_MODEL", file=sys.stderr)
            continue
        res = run_mode(mode, out_dir)
        (out_dir / "summary.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        results.append(res)
        for s in res["scenarios"]:
            bad = [c for c in s["checks"] if not c["ok"]]
            print(f"[{mode}] {s['id']}: {'PASS' if s['pass'] else 'FAIL'} red={s['levels']['red']}/{s['alerts']}"
                  + (f"  失败: {bad}" if bad else ""))
        for q in res["questions"]:
            print(f"[{mode}] {q['id']}: {'PASS' if q['pass'] else 'FAIL'} 期望 {q['expected']} 实得 {q['got']}")
    text = report(results)
    (Path(args.out) / "report.md").write_text(text + "\n\n调用统计：" + json.dumps(cache.STATS, ensure_ascii=False),
                                              encoding="utf-8")
    print("\n" + text)


if __name__ == "__main__":
    main()
