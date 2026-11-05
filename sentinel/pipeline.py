"""Wire the static and dynamic steps together.

modes (used for the ablation in eval.py):
  osv     baseline: every OSV hit is an alert, HIGH/CRITICAL shown as urgent (what audit tools do)
  static  + KEV / EPSS / import check / advisory-regex symbols / evidence gate  (no LLM, no search)
  full    + Yuanbao search planned and read by the LLM, LLM reachability vote, all checked by the gate
"""

from pathlib import Path

from . import agent, gate, intel, llm, reach, scanners
from .inventory import Package, load_repo

_CARDS: dict[tuple, dict] = {}


def scan(repo_path: Path, mode: str = "full", inject: list[dict] | None = None,
         scanner: list[dict] | None = None) -> dict:
    """scanner: entries from scanners.load(); when given, only the pairs that scanner reported are triaged."""
    repo = load_repo(repo_path)
    use_llm = mode == "full" and llm.enabled()
    use_search = mode == "full"
    if scanner is not None:
        _add_scanner_packages(repo, scanner)
    ids = intel.osv_query(repo.packages)
    findings = []
    for pkg, vids in zip(repo.packages, ids):
        for v in intel.normalize(pkg, vids) if vids else []:
            findings.append({"package": pkg, "vuln": v})
    unmatched = []
    if scanner is not None:
        findings, unmatched = _match_scanner(findings, scanner)
    cves = [c for f in findings for c in f["vuln"]["cves"]]
    kev, scores = intel.kev(), intel.epss(cves) if cves else {}
    import_cache: dict[str, list] = {}
    stats = {"findings": len(findings), "cards_built": 0, "cards_skipped_prefilter": 0, "llm_calls": 0}

    for f in findings:
        pkg, v = f["package"], f["vuln"]
        v["kev"] = any(c in kev for c in v["cves"])
        v["epss"] = max((scores.get(c, 0.0) for c in v["cves"]), default=0.0)
        if mode == "osv":
            f["decision"] = {"level": "red" if v["severity"] in ("CRITICAL", "HIGH") else "yellow",
                             "reason": f"漏洞库严重度 {v['severity'] or '未知'}", "vex_status": "affected",
                             "vex_justification": "", "exploitation": {"signals": []}}
            continue
        key = pkg.ecosystem + pkg.name
        if key not in import_cache:
            import_cache[key] = reach.imports(repo.path, pkg.ecosystem, pkg.name) if pkg.direct else []
        f["import_hits"] = import_cache[key]
        worth = not v["malware"] and not pkg.dev and (f["import_hits"] or not pkg.direct)
        if worth:
            ck = (mode, use_llm, pkg.ecosystem, pkg.name, pkg.version, v["id"], bool(inject))
            if ck not in _CARDS:
                _CARDS[ck] = agent.build_card(pkg, v, use_llm, use_search, inject)
                stats["cards_built"] += 1
                stats["llm_calls"] += _CARDS[ck]["llm_calls"]
            f["card"] = _CARDS[ck]
            symbols = f["card"]["vulnerable_symbols"]
            hits = reach.calls(repo.path, pkg.ecosystem, symbols) if symbols and pkg.direct else []
            f["call_hits"] = hits
            if not symbols or not pkg.direct:
                f["reach"] = {"reachable": "unknown", "reason_zh": "无具体漏洞函数或为间接依赖"}
            elif use_llm:
                deps = sorted({f"{p.name}@{p.version}" for p in repo.packages})
                f["reach"] = agent.judge(pkg, f["card"], hits, repo.exposure, deps=deps)
                stats["llm_calls"] += len(f["reach"].get("votes", []))
            else:
                f["reach"] = {"reachable": "yes" if hits else "no-static",
                              "reason_zh": "静态命中漏洞函数调用" if hits else "静态检索未发现漏洞函数调用",
                              "evidence": [f"{h['file']}:{h['line']}" for h in hits]}
        else:
            stats["cards_skipped_prefilter"] += 1
        f["decision"] = gate.decide(f)
    return {"repo": repo, "mode": mode, "llm": use_llm, "findings": findings, "stats": stats,
            "scanner_unmatched": unmatched}


def _add_scanner_packages(repo, scanner: list[dict]) -> None:
    """A scanner may see packages our own discovery missed; triage those too instead of dropping them."""
    have = {(p.ecosystem, scanners.norm(p.ecosystem, p.name), p.version) for p in repo.packages}
    for e in scanner:
        key = (e["ecosystem"], scanners.norm(e["ecosystem"], e["name"]), e["version"])
        if key not in have:
            have.add(key)
            repo.packages.append(Package(e["ecosystem"], e["name"], e["version"], direct=False,
                                         source="scanner:" + e["path"]))


def _match_scanner(findings: list[dict], scanner: list[dict]) -> tuple[list[dict], list[dict]]:
    """Mark which findings the scanner also reported (f["by_scanner"]); our own discovery's extra findings
    are kept, not dropped. Also return scanner entries OSV could not explain."""
    want: dict[tuple, set] = {}
    for e in scanner:
        want.setdefault((e["ecosystem"], scanners.norm(e["ecosystem"], e["name"]), e["version"]), set()).update(e["ids"])
    kept, seen = [], set()
    for f in findings:
        p, v = f["package"], f["vuln"]
        key = (p.ecosystem, scanners.norm(p.ecosystem, p.name), p.version)
        hit = want.get(key, set()) & {v["id"], *v["aliases"], *v["cves"]}
        f["by_scanner"] = bool(hit)
        kept.append(f)
        seen |= {(key, i) for i in hit}
    unmatched = [{"package": f"{k[0]}/{k[1]}@{k[2]}", "id": i} for k, ids in want.items() for i in sorted(ids)
                 if (k, i) not in seen]
    return kept, unmatched


def ask(question: str, repo_paths: list[Path], mode: str = "full") -> dict:
    """Answer "are we affected?" for a forwarded article / question across all repos."""
    use_llm = mode == "full" and llm.enabled()
    parsed = agent.parse_question(question, use_llm, mode == "full")
    cves, names = set(parsed["cves_explicit"]), {c["name"].lower() for c in parsed["components"]}
    hits, used = [], []
    for path in repo_paths:
        result = scan(path, mode)
        for f in result["findings"]:
            v, pkg = f["vuln"], f["package"]
            by_cve = cves & {*v["cves"], *v["aliases"], v["id"]}
            by_name = not cves and _name_match(pkg.name, names)
            if by_cve or by_name:
                hits.append((result["repo"], f))
        for pkg in result["repo"].packages:
            if _name_match(pkg.name, names) or (cves and any(f["package"] is pkg and cves & set(f["vuln"]["cves"])
                                                             for _, f in hits)):
                used.append((result["repo"], pkg))
    return {"question": question, "parsed": parsed, "hits": hits, "used": used}


def _name_match(pkg_name: str, names: set[str]) -> bool:
    n = pkg_name.lower()
    return any(x and (x == n or n.endswith(":" + x) or x.endswith(":" + n.split(":")[-1])
                      or x == n.split(":")[-1]) for x in names)
