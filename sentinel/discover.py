"""Static step 0: point it at any code directory, find every project and every library in it.

Evidence used, most precise first:
  lockfiles / manifests        package-lock.json, package.json, requirements*.txt, pom.xml
  installed copies             node_modules/**/package.json, site-packages/*.dist-info/METADATA
  vendored jars                META-INF/maven/<group>/<artifact>/pom.properties inside every *.jar
  source imports               imports that no manifest declares (reported, not version-matched)
"""

import json
import re
import sys
import zipfile
from pathlib import Path

from .inventory import Package

MANIFESTS = ("package-lock.json", "package.json", "pom.xml", "requirements.txt")
SKIP = {".git", "node_modules", "__pycache__", "dist", "build", "target", ".venv", "venv", "site-packages", ".verify"}
NODE_BUILTINS = {"fs", "path", "http", "https", "url", "os", "crypto", "util", "events", "stream", "child_process",
                 "net", "zlib", "buffer", "assert", "querystring", "readline", "tls", "dns", "cluster", "worker_threads"}


def find_projects(root: Path) -> list[Path]:
    """Directories holding a manifest or vendored jars; a bare code folder counts as one project."""
    found = []
    for d in [root, *sorted(p for p in root.rglob("*") if p.is_dir())]:
        if SKIP & set(d.relative_to(root).parts):
            continue
        has_manifest = any((d / m).exists() for m in MANIFESTS) or any(d.glob("requirements*.txt"))
        # no manifest at all, but libraries are installed next to the code
        has_installed = (d / "node_modules").is_dir() or any((d / v).is_dir() for v in (".venv", "venv"))
        if has_manifest or has_installed:
            found.append(d)
    # jars copied in outside any project (e.g. an old webapp's lib/) form a project of their own
    for jar in sorted(root.rglob("*.jar")):
        if SKIP & set(jar.relative_to(root).parts) or any(f in jar.parents for f in found):
            continue
        home = jar.parent.parent if jar.parent.name.lower() in ("lib", "libs", "jars") else jar.parent
        if home.name.upper() == "WEB-INF" and home != root:
            home = home.parent
        if home not in found:
            found.append(home)
    return found or [root]


def installed_npm(project: Path) -> list[Package]:
    pkgs = []
    nm = project / "node_modules"
    if not nm.is_dir():
        return pkgs
    for pj in sorted(nm.rglob("package.json")):
        parts = pj.relative_to(nm).parts
        # node_modules/<name>/package.json or node_modules/@scope/<name>/package.json (nested copies too)
        if len(parts) < 2 or "node_modules" in parts[-2:]:
            continue
        try:
            meta = json.loads(pj.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if meta.get("name") and meta.get("version"):
            pkgs.append(Package("npm", meta["name"], meta["version"], False, False, pj.relative_to(project).as_posix()))
    return pkgs


def installed_python(project: Path) -> list[Package]:
    pkgs = []
    for meta in sorted(project.rglob("*.dist-info/METADATA")):
        text = meta.read_text(encoding="utf-8", errors="ignore")
        name = re.search(r"^Name:\s*(\S+)", text, re.M)
        ver = re.search(r"^Version:\s*(\S+)", text, re.M)
        if name and ver:
            pkgs.append(Package("PyPI", name.group(1), ver.group(1), False, False, meta.relative_to(project).as_posix()))
    return pkgs


def vendored_jars(project: Path) -> list[Package]:
    """Copied-in jars carry their real coordinates in pom.properties, whatever the file is called."""
    pkgs = []
    for jar in sorted(project.rglob("*.jar")):
        if {".git", "node_modules"} & set(jar.relative_to(project).parts):
            continue
        try:
            with zipfile.ZipFile(jar) as z:
                for n in z.namelist():
                    if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
                        props = dict(line.split("=", 1) for line in z.read(n).decode("utf-8", "ignore").splitlines()
                                     if "=" in line and not line.startswith("#"))
                        if {"groupId", "artifactId", "version"} <= props.keys():
                            pkgs.append(Package("Maven", f"{props['groupId'].strip()}:{props['artifactId'].strip()}",
                                                props["version"].strip(), False, True, jar.relative_to(project).as_posix()))
        except (zipfile.BadZipFile, OSError):
            continue
    return pkgs


def undeclared_imports(project: Path, declared: list[Package]) -> list[dict]:
    """Third-party imports in source that no manifest or installed copy accounts for."""
    names = {p.name.lower() for p in declared} | {p.name.split(":")[-1].lower() for p in declared}
    from .reach import PY_MODULES
    py_names = names | {PY_MODULES.get(n, n.replace("-", "_")) for n in names}
    out: dict[str, dict] = {}
    for f in sorted(project.rglob("*")):
        if not f.is_file() or SKIP & set(f.relative_to(project).parts):
            continue
        if f.suffix == ".py":
            for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z_]\w*)", f.read_text(encoding="utf-8", errors="ignore"), re.M):
                mod = m.group(1)
                local = (project / mod).exists() or (project / f"{mod}.py").exists()
                if mod.lower() not in py_names and mod not in sys.stdlib_module_names and not local:
                    out.setdefault(f"PyPI:{mod}", {"ecosystem": "PyPI", "name": mod, "where": f.relative_to(project).as_posix()})
        elif f.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue"):
            for m in re.finditer(r"(?:require\(\s*|from\s+|import\s+)['\"]([^'\"./][^'\"]*)['\"]",
                                 f.read_text(encoding="utf-8", errors="ignore")):
                spec = m.group(1).removeprefix("node:")
                pkg = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
                if pkg.lower() not in names and pkg not in NODE_BUILTINS:
                    out.setdefault(f"npm:{pkg}", {"ecosystem": "npm", "name": pkg, "where": f.relative_to(project).as_posix()})
    return list(out.values())
