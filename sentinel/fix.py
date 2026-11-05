"""Step 6: turn a proven fix into something a person can merge with one click.

We only write a patch when the sandbox proved the attack is blocked after the upgrade
and the project's own smoke test still passes. The patch bumps the dependency in its
manifest (package.json / requirements*.txt / pom.xml) and is a plain unified diff that
`git apply` accepts, so delivery is "open a branch / PR", not "ping someone on chat".
"""

import difflib
import re
from pathlib import Path


def _diff(rel: str, before: str, after: str) -> str:
    out = difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                               fromfile=f"a/{rel}", tofile=f"b/{rel}")
    return "".join(out)


def _bump_npm(text: str, name: str, version: str) -> str:
    return re.sub(rf'("{re.escape(name)}"\s*:\s*")[\^~>=<\s]*[^"]+(")',
                  lambda m: f"{m.group(1)}{version}{m.group(2)}", text, count=1)


def _bump_requirements(text: str, name: str, version: str) -> str:
    return re.sub(rf"(?im)^(\s*{re.escape(name)}\s*)==\s*[^\s;#]+",
                  lambda m: f"{m.group(1)}=={version}", text, count=1)


def _bump_pom(text: str, name: str, version: str) -> str:
    artifact = name.split(":")[-1]
    pat = re.compile(rf"(<artifactId>\s*{re.escape(artifact)}\s*</artifactId>\s*<version>\s*)[^<]+(\s*</version>)",
                     re.S)
    return pat.sub(lambda m: f"{m.group(1)}{version}{m.group(2)}", text, count=1)


_BUMP = {"package.json": _bump_npm, "requirements": _bump_requirements, "pom.xml": _bump_pom}


def _manifest(repo_path: Path, ecosystem: str, name: str) -> Path | None:
    if ecosystem == "npm":
        return repo_path / "package.json" if (repo_path / "package.json").exists() else None
    if ecosystem == "PyPI":
        for p in sorted(repo_path.glob("requirements*.txt")):
            if re.search(rf"(?im)^\s*{re.escape(name)}\s*==", p.read_text(encoding="utf-8")):
                return p
    if ecosystem == "Maven":
        return repo_path / "pom.xml" if (repo_path / "pom.xml").exists() else None
    return None


def make_patch(repo_path: Path, ecosystem: str, name: str, version: str) -> dict:
    """Return {ok, patch, file, before, after} for bumping `name` to `version`."""
    manifest = _manifest(repo_path, ecosystem, name)
    if not manifest:
        return {"ok": False, "why": "找不到可改的依赖清单（可能是改名拷进来的 jar，需手动替换）"}
    before = manifest.read_text(encoding="utf-8")
    bump = _bump_requirements if manifest.name.startswith("requirements") else _BUMP[manifest.name]
    after = bump(before, name, version)
    if after == before:
        return {"ok": False, "why": f"清单里没有可改的 {name} 版本声明"}
    rel = manifest.relative_to(repo_path).as_posix()
    return {"ok": True, "file": rel, "patch": _diff(rel, before, after), "manifest": str(manifest),
            "before_text": before, "after_text": after}


def branch_name(repo_name: str, cve: str, name: str) -> str:
    safe = re.sub(r"[^\w.-]", "-", f"{name}")
    return f"depfix/{repo_name}/{cve or safe}".lower()
