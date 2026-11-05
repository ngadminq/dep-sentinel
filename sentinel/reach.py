"""Static step 3: is the package imported, and is the vulnerable symbol called?

Deliberately simple (regex over source files) so it runs anywhere; every hit is a
file:line the reviewer can open. It cannot see reflection or dynamic imports, which
is why "not found" never becomes "not affected" on its own.
"""

import re
from pathlib import Path

EXTS = {"npm": {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".html"},
        "PyPI": {".py"}, "Maven": {".java", ".kt"}}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "target", "__pycache__", "venv", ".venv", ".verify"}
PY_MODULES = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "python-dateutil": "dateutil",
              "scikit-learn": "sklearn", "opencv-python": "cv2", "pyjwt": "jwt"}


def source_files(repo: Path, ecosystem: str) -> list[Path]:
    exts = EXTS.get(ecosystem, set())
    files = []
    for p in sorted(repo.rglob("*")):
        rel = p.relative_to(repo).parts
        if p.is_file() and p.suffix in exts and not SKIP_DIRS & set(rel) \
                and not any(part in ("test", "tests", "__tests__") for part in rel[:-1]):
            files.append(p)
    return sorted(files)


def _import_patterns(ecosystem: str, name: str) -> list[str]:
    if ecosystem == "npm":
        n = re.escape(name)
        return [rf"require\(\s*['\"]{n}(/[^'\"]*)?['\"]", rf"from\s+['\"]{n}(/[^'\"]*)?['\"]",
                rf"import\s+['\"]{n}(/[^'\"]*)?['\"]", rf"<script[^>]+src=[^>]*{n}[\w.\-]*\.js"]
    if ecosystem == "PyPI":
        mod = re.escape(PY_MODULES.get(name.lower(), name.lower().replace("-", "_")))
        return [rf"^\s*import\s+{mod}\b", rf"^\s*from\s+{mod}(\.\w+)*\s+import\b"]
    if ecosystem == "Maven":
        group = name.split(":")[0]
        return [rf"^\s*import\s+{re.escape(group)}\."]
    return []


def _grep(files: list[Path], repo: Path, patterns: list[str], limit: int = 20) -> list[dict]:
    hits = []
    regs = [re.compile(p, re.M) for p in patterns]
    for f in files:
        lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines):
            if any(r.search(line) for r in regs):
                hits.append({"file": f.relative_to(repo).as_posix(), "line": i + 1, "code": line.strip()[:200],
                             "context": "\n".join(lines[max(0, i - 4): i + 5])})
                if len(hits) >= limit:
                    return hits
    return hits


def imports(repo: Path, ecosystem: str, name: str) -> list[dict]:
    return _grep(source_files(repo, ecosystem), repo, _import_patterns(ecosystem, name))


def symbol_patterns(symbols: list[str]) -> list[str]:
    """`_.template` / `yaml.load` -> call-site regex on the last segment; `FullLoader` (a class) -> any use."""
    pats = []
    for s in symbols:
        last = re.split(r"[.#:]", s.strip("`() "))[-1]
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", last or ""):
            continue
        if last[0].isupper():
            pats.append(rf"(?<![\w$]){re.escape(last)}(?![\w$])")
        else:
            pats.append(rf"(?<![\w$]){re.escape(last)}\s*\(")
    return pats


def calls(repo: Path, ecosystem: str, symbols: list[str]) -> list[dict]:
    pats = symbol_patterns(symbols)
    return _grep(source_files(repo, ecosystem), repo, pats) if pats else []
