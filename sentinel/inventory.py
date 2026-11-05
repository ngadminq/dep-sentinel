"""Static step 1: build the asset inventory (repo x package x version x scope x owner)."""

import json
import re
import subprocess
from collections import Counter
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Package:
    ecosystem: str          # npm / PyPI / Maven / runtime
    name: str
    version: str
    dev: bool = False
    direct: bool = True
    source: str = ""        # manifest file the entry came from


@dataclass
class Repo:
    path: Path
    name: str
    owner: dict
    exposure: str           # internet / internal / unknown
    packages: list[Package] = field(default_factory=list)
    undeclared: list[dict] = field(default_factory=list)   # imported in code, declared nowhere


def _npm(repo: Path) -> list[Package]:
    lock, manifest = repo / "package-lock.json", repo / "package.json"
    pkgs: list[Package] = []
    if lock.exists():
        data = json.loads(lock.read_text(encoding="utf-8"))
        root = data.get("packages", {}).get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
        for key, meta in data.get("packages", {}).items():
            if not key or "version" not in meta:
                continue
            name = key.split("node_modules/")[-1]
            pkgs.append(Package("npm", name, meta["version"], bool(meta.get("dev")), name in direct,
                                "package-lock.json"))
    elif manifest.exists():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        for section, dev in (("dependencies", False), ("devDependencies", True)):
            for name, spec in data.get(section, {}).items():
                pkgs.append(Package("npm", name, re.sub(r"^[\^~>=<\s]+", "", spec), dev, True, "package.json"))
    return pkgs


def _pypi(repo: Path) -> list[Package]:
    pkgs = []
    for path in sorted(repo.glob("requirements*.txt")):
        dev = any(t in path.stem for t in ("dev", "test"))
        for line in path.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
            if m:
                pkgs.append(Package("PyPI", m.group(1), m.group(2), dev, True, path.name))
    return pkgs


def _maven(repo: Path) -> list[Package]:
    pom = repo / "pom.xml"
    if not pom.exists():
        return []
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    tree = ET.parse(pom)
    pkgs = []
    for dep in tree.findall(".//m:dependencies/m:dependency", ns):
        get = lambda tag: (dep.findtext(f"m:{tag}", default="", namespaces=ns) or "").strip()
        if get("version"):
            pkgs.append(Package("Maven", f"{get('groupId')}:{get('artifactId')}", get("version"),
                                get("scope") == "test", True, "pom.xml"))
    return pkgs


def _runtime(repo: Path) -> list[Package]:
    docker = repo / "Dockerfile"
    if not docker.exists():
        return []
    pkgs = []
    for m in re.finditer(r"^FROM\s+([\w./-]+):([\w.\-]+)", docker.read_text(encoding="utf-8"), re.M):
        pkgs.append(Package("runtime", m.group(1).split("/")[-1], m.group(2), False, True, "Dockerfile"))
    return pkgs


def _owner(repo: Path, meta: dict) -> dict:
    """.sentinel.json > CODEOWNERS > the most frequent committer of the last 90 days."""
    if meta.get("owner"):
        return meta["owner"]
    for path in (repo / "CODEOWNERS", repo / ".github" / "CODEOWNERS"):
        if path.exists():
            m = re.search(r"^\*\s+@(\S+)", path.read_text(encoding="utf-8"), re.M)
            if m:
                return {"name": m.group(1)}
    try:
        log = subprocess.run(["git", "-C", str(repo), "log", "--since=90.days", "--format=%an|%ae", "--", "."],
                             capture_output=True, text=True, timeout=20).stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        log = []
    if log:
        name, email = Counter(log).most_common(1)[0][0].split("|", 1)
        return {"name": name, "email": email, "from": "git 最近 90 天提交最多"}
    return {"name": "未指定"}


def load_repo(path: Path) -> Repo:
    meta_path = path / ".sentinel.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    repo = Repo(path, meta.get("name", path.name), _owner(path, meta), meta.get("exposure", "unknown"))
    from . import discover
    declared = _npm(path) + _pypi(path) + _maven(path) + _runtime(path)
    found = (discover.installed_npm(path) if not (path / "package-lock.json").exists() else [])         + discover.installed_python(path) + discover.vendored_jars(path)
    seen = {(p.ecosystem, p.name.lower(), p.version) for p in declared}
    extra = []
    for p in found:
        key = (p.ecosystem, p.name.lower(), p.version)
        if key not in seen:
            seen.add(key)
            extra.append(p)
    # Installed copies have no "direct" flag: treat a library as direct when the code imports it,
    # otherwise as something another library pulled in.
    from .reach import imports
    for p in extra:
        if p.ecosystem != "Maven":
            p.direct = bool(imports(path, p.ecosystem, p.name))
    repo.packages = declared + extra
    repo.undeclared = discover.undeclared_imports(path, repo.packages)
    return repo
