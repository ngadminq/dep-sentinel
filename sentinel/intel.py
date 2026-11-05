"""Static step 2: deterministic intelligence — OSV version match, CISA KEV, EPSS."""

import re

from .cache import cached, http_json
from .inventory import Package

OSV = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="


def osv_query(pkgs: list[Package]) -> list[list[str]]:
    """Return OSV vulnerability ids for each package (runtime images are skipped)."""
    queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
               for p in pkgs if p.ecosystem != "runtime"]
    found: list[list[str]] = []
    for i in range(0, len(queries), 500):
        chunk = queries[i:i + 500]
        rec = cached("osv-batch", {"queries": chunk},
                     lambda: http_json(f"{OSV}/querybatch", {"queries": chunk}))
        found += [[v["id"] for v in r.get("vulns", [])] for r in rec["response"]["results"]]
    found.reverse()
    return [[] if p.ecosystem == "runtime" else found.pop() for p in pkgs]


def osv_vuln(vid: str) -> dict:
    return cached("osv-vuln", {"id": vid}, lambda: http_json(f"{OSV}/vulns/{vid}"))["response"]


def vkey(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", v)[:4])


def _fixed(vuln: dict, pkg: Package) -> list[str]:
    """Fixed versions above the installed one, nearest first (the upgrade to recommend is [0])."""
    fixed = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != pkg.name.lower():
            continue
        for rng in aff.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted({f for f in fixed if vkey(f) > vkey(pkg.version)}, key=vkey)


def normalize(pkg: Package, ids: list[str]) -> list[dict]:
    """Fetch details and merge aliases (GHSA / PYSEC / CVE of the same flaw)."""
    groups: list[dict] = []
    for vid in ids:
        v = osv_vuln(vid)
        names = {v["id"], *v.get("aliases", [])}
        for g in groups:
            if g["names"] & names:
                g["names"] |= names
                g["raw"].append(v)
                break
        else:
            groups.append({"names": names, "raw": [v]})
    vulns = []
    for g in groups:
        main = next((v for v in g["raw"] if v["id"].startswith("GHSA")), g["raw"][0])
        cves = sorted(n for n in g["names"] if n.startswith("CVE-"))
        text = " ".join([main.get("summary", ""), main.get("details", "")])
        vulns.append({
            "id": main["id"], "cves": cves, "aliases": sorted(g["names"] - {main["id"]}),
            "summary": main.get("summary", "") or main.get("details", "")[:120],
            "details": main.get("details", "")[:2500],
            "severity": (main.get("database_specific") or {}).get("severity", ""),
            "fixed": _fixed(main, pkg),
            "malware": any(n.startswith("MAL-") for n in g["names"])
                       or bool(re.match(r"\s*(embedded )?malicious (code|package)", text, re.I)),
            "references": [r["url"] for r in main.get("references", [])][:8],
            "published": min((v.get("published", "") for v in g["raw"] if v.get("published")), default=""),
        })
    return vulns


_KEV: dict | None = None


def kev() -> dict[str, dict]:
    global _KEV
    if _KEV is None:
        rec = cached("kev", {"url": KEV_URL}, lambda: http_json(KEV_URL), ttl_hours=24)
        _KEV = {v["cveID"]: v for v in rec["response"]["vulnerabilities"]}
    return _KEV


def epss(cves: list[str]) -> dict[str, float]:
    cves = sorted(set(cves))
    scores: dict[str, float] = {}
    for i in range(0, len(cves), 80):
        chunk = cves[i:i + 80]
        rec = cached("epss", {"cves": chunk}, lambda: http_json(EPSS_URL + ",".join(chunk)), ttl_hours=24)
        scores |= {d["cve"]: float(d["epss"]) for d in rec["response"].get("data", [])}
    return scores
