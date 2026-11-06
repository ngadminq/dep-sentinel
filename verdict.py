"""Print one scenario's code and how the rules-only and full pipelines judged one CVE (reads out/eval/).

  python verdict.py s11-template-constant CVE-2021-23337
"""

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
LEVEL = {"red": "今天修", "yellow": "本周修", "white": "只记录"}

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    scenario, cve = sys.argv[1], sys.argv[2]
    for src in sorted((BASE / "scenarios" / scenario / "src").glob("*")):
        print(f"# {src.relative_to(BASE / 'scenarios' / scenario).as_posix()}")
        print(src.read_text(encoding="utf-8").rstrip())
    print()
    for mode, label in (("static", "只用规则"), ("full", "规则+大模型+元宝")):
        d = json.loads((BASE / "out" / "eval" / mode / f"{scenario}.json").read_text(encoding="utf-8"))
        r = next(x for x in d["rows"] if cve in x["cves"])
        votes = f"，投票 {r['tally']['yes']}:{r['tally']['no']}" if r.get("tally") else ""
        print(f"[{label}] {LEVEL[r['level']]}{votes}")
        print(f"  {r['reach_reason']}")
