"""Outputs: DingTalk markdown, OpenVEX, and a JSON audit record."""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse

from .cache import http_json
from .intel import vkey

ICON = {"red": "🔴 今天修", "yellow": "🟡 本周", "white": "⚪ 记录"}


def finding_row(f: dict) -> dict:
    p, v, d = f["package"], f["vuln"], f["decision"]
    card, r = f.get("card") or {}, f.get("reach") or {}
    return {"package": f"{p.ecosystem}/{p.name}@{p.version}", "dev": p.dev, "direct": p.direct, "source": p.source,
            "vuln": v["id"], "cves": v["cves"], "severity": v["severity"], "kev": v.get("kev"),
            "epss": round(v.get("epss", 0), 4), "malware": v["malware"],
            "fixed": (v["fixed"] or [card.get("fixed_version", "")])[0], "level": d["level"], "reason": d["reason"],
            "signals": d["exploitation"].get("signals", []), "vex": d["vex_status"],
            "symbols": card.get("vulnerable_symbols", []), "reachable": r.get("reachable"),
            "reach_reason": r.get("reason_zh", ""), "reach_evidence": r.get("evidence", []),
            "tally": r.get("tally"), "imports": [f"{h['file']}:{h['line']}" for h in f.get("import_hits", [])][:3],
            "web_evidence": card.get("exploit_evidence", []), "dropped_evidence": len(card.get("dropped_evidence", [])),
            "searches": card.get("searches", []), "summary_zh": card.get("summary_zh", v["summary"])}


def _fix_cmd(row: dict) -> str:
    eco, rest = row["package"].split("/", 1)
    name = rest.rsplit("@", 1)[0]
    if not row["fixed"]:
        return "暂无修复版本，先下线或替换"
    if row.get("source", "").endswith(".jar"):     # vendored jar: there is no manifest to edit
        return f"把 {row['source']} 换成 {name} {row['fixed']} 的 jar"
    return {"npm": f"npm i {name}@{row['fixed']}", "PyPI": f"pip install '{name}>={row['fixed']}'",
            "Maven": f"pom.xml 中 {name} 升级到 {row['fixed']}"}.get(eco, f"升级到 {row['fixed']}")


def dingtalk_markdown(result: dict) -> dict:
    """One message per repo scan; red items @owner, yellow/white only counted."""
    repo = result["repo"]
    rows = [finding_row(f) for f in result["findings"]]
    reds = [r for r in rows if r["level"] == "red"]
    yellows = [r for r in rows if r["level"] == "yellow"]
    whites = [r for r in rows if r["level"] == "white"]
    owner = repo.owner
    at = f" @{owner['mobile']}" if owner.get("mobile") else f" @{owner.get('name', '')}"
    lines = [f"### {'🔴' if reds else '✅'} {repo.name}：{len(reds)} 件需今天处理",
             f"> 漏洞库原始告警 {len(rows)} 条 → 今天修 {len(reds)} / 本周 {len(yellows)} / 仅记录 {len(whites)}", ""]
    seen = set()
    for r in reds:
        if r["package"] in seen:
            continue
        seen.add(r["package"])
        same = [x for x in reds if x["package"] == r["package"]]
        # one upgrade that clears every known issue of this package, not just the red ones
        fixes = [x["fixed"] for x in rows if x["package"] == r["package"] and x["fixed"]]
        r = r | {"fixed": max(fixes, key=vkey) if fixes else ""}
        found = f"，来自 {r['source']}" if r.get("source", "").endswith((".jar", "METADATA", "package.json"))             and "/" in r.get("source", "") else ""
        lines += [f"**{r['package']}**（{', '.join(x['cves'][0] if x['cves'] else x['vuln'] for x in same)}{found}）",
                  f"- 结论：{r['reason']}", f"- 依据：{'；'.join(r['signals']) or '恶意包'}"]
        if r["reach_evidence"]:
            lines.append(f"- 调用位置：{', '.join(r['reach_evidence'][:3])}")
        for e in r["web_evidence"][:2]:
            lines.append(f"- 来源：[{e['domain']}]({e['url']})")
        lines += [f"- 修复：`{_fix_cmd(r)}`", ""]
    if reds:
        lines.append(f"负责人：{at.strip()}")
    return {"msgtype": "markdown", "markdown": {"title": f"{repo.name} 依赖安全", "text": "\n".join(lines)},
            "at": {"atMobiles": [owner["mobile"]] if reds and owner.get("mobile") else []}}


def send_dingtalk(payload: dict) -> str:
    """Send when DINGTALK_WEBHOOK is set (with optional DINGTALK_SECRET signing); else dry-run."""
    url = os.environ.get("DINGTALK_WEBHOOK", "")
    if not url:
        return "dry-run"
    secret = os.environ.get("DINGTALK_SECRET", "")
    if secret:
        ts = str(round(time.time() * 1000))
        sign = base64.b64encode(hmac.new(secret.encode(), f"{ts}\n{secret}".encode(), hashlib.sha256).digest())
        url += f"&timestamp={ts}&sign={urllib.parse.quote_plus(sign)}"
    return json.dumps(http_json(url, payload), ensure_ascii=False)


def openvex(result: dict) -> dict:
    """OpenVEX v0.2.0 document that Trivy / Grype can consume to suppress triaged noise."""
    stmts = []
    for f in result["findings"]:
        d, p, v = f["decision"], f["package"], f["vuln"]
        purl_type = {"npm": "npm", "PyPI": "pypi", "Maven": "maven"}.get(p.ecosystem)
        if not purl_type:
            continue
        name = p.name.replace(":", "/") if purl_type == "maven" else p.name
        stmt = {"vulnerability": {"name": (v["cves"] or [v["id"]])[0], "aliases": [v["id"]]},
                "products": [{"@id": f"pkg:{purl_type}/{name}@{p.version}"}], "status": d["vex_status"]}
        if d["vex_status"] == "not_affected":
            stmt["justification"] = d["vex_justification"]
            stmt["impact_statement"] = d["reason"]
        elif d["vex_status"] == "affected":
            stmt["action_statement"] = f"升级到 {(v['fixed'] or ['最新版'])[0]}"
        else:
            stmt["status_notes"] = d["reason"]
        stmts.append(stmt)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"urn:dep-sentinel:{result['repo'].name}",
            "author": "dep-sentinel", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "version": 1, "statements": stmts}
