"""Read the JSON report of a scanner the team already runs (Trivy, Grype) and hand it to the pipeline.

The scanner decides *which* (package, vulnerability) pairs exist; dep-sentinel only decides which of
them need a person today. Each report entry becomes {ecosystem, name, version, ids, path}.
"""

import json
import re
from pathlib import Path

_TRIVY_TYPES = {"npm": "npm", "node-pkg": "npm", "yarn": "npm", "pnpm": "npm",
                "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "python-pkg": "PyPI",
                "pom": "Maven", "jar": "Maven", "gradle": "Maven"}
_PURL_TYPES = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}


def norm(ecosystem: str, name: str) -> str:
    """Package names as the three ecosystems compare them."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower() if ecosystem == "npm" else name


def load(path: Path) -> tuple[str, list[dict]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "Results" in data:
        return "trivy", _trivy(data)
    if "matches" in data:
        return "grype", _grype(data)
    raise ValueError(f"{path}: 不是 Trivy 或 Grype 的 JSON 报告")


def _trivy(data: dict) -> list[dict]:
    out = []
    for res in data.get("Results") or []:
        eco = _TRIVY_TYPES.get(res.get("Type", ""))
        for v in res.get("Vulnerabilities") or []:
            if not eco:
                continue
            out.append({"ecosystem": eco, "name": v["PkgName"], "version": v["InstalledVersion"],
                        "ids": {v["VulnerabilityID"]}, "severity": v.get("Severity", ""),
                        "path": v.get("PkgPath") or res.get("Target", "")})
    return out


def _grype(data: dict) -> list[dict]:
    out = []
    for m in data["matches"]:
        art, vul = m["artifact"], m["vulnerability"]
        purl = art.get("purl", "")
        eco = _PURL_TYPES.get(purl[4:].split("/", 1)[0]) if purl.startswith("pkg:") else None
        if not eco:
            continue
        name = art["name"]
        if eco == "Maven":      # pkg:maven/group/artifact@version
            group, artifact = purl[len("pkg:maven/"):].split("@")[0].split("/")[:2]
            name = f"{group}:{artifact}"
        ids = {vul["id"], *(r["id"] for r in m.get("relatedVulnerabilities", []))}
        locs = art.get("locations") or [{}]
        out.append({"ecosystem": eco, "name": name, "version": art["version"], "ids": ids,
                    "severity": vul.get("severity", ""), "path": locs[0].get("path", "")})
    return out


def by_project(entries: list[dict], projects: list[Path], root: Path) -> dict[Path, list[dict]]:
    """Attach each report entry to the deepest discovered project whose folder contains its path."""
    rel = sorted(((p, p.resolve().relative_to(root.resolve()).as_posix()) for p in projects),
                 key=lambda x: -len(x[1]))
    groups: dict[Path, list[dict]] = {}
    for e in entries:
        path = e["path"].replace("\\", "/").lstrip("/")
        for proj, prefix in rel:
            if prefix in ("", ".") or path == prefix or path.startswith(prefix + "/"):
                groups.setdefault(proj, []).append(e)
                break
    return groups
