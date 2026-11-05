"""Step 5: sandbox rehearsal. For a red finding with a verify spec, prove the fix works.

For each fix we run two phases in a throwaway directory, with no network:
  vulnerable  install the version in use, run the attack  -> expect EXPLOITED
  fixed       install the recommended version, run the attack again and the project's
              own smoke test                              -> expect BLOCKED + test pass

The attack scripts never do anything harmful; they make a benign marker (a file, a
polluted property) and report EXPLOITED / BLOCKED. Packages are installed from a
vendored directory (SENTINEL_VENDOR) so the whole thing runs under `--network none`.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PYTHON = os.environ.get("SANDBOX_PYTHON", "py -3" if os.name == "nt" else "python3")
NODE = os.environ.get("SANDBOX_NODE", "node")
NPM = os.environ.get("SANDBOX_NPM", "npm.cmd" if os.name == "nt" else "npm")
VENDOR = Path(os.environ.get("SENTINEL_VENDOR", Path(__file__).resolve().parent.parent / "vendor"))
TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "300"))


VERIFY_DIR = ".verify"


def load_spec(scenario_dir: Path) -> dict | None:
    path = scenario_dir / "verify.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _asset(scenario_dir: Path, name: str) -> Path:
    """Attack / test scripts live in .verify/ so the reachability scan never sees them."""
    return scenario_dir / VERIFY_DIR / name


def _run(cmd: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT,
                          env={**os.environ, **(env or {})})


def _verdict(out: str) -> str:
    """Last non-empty stdout line decides: EXPLOITED / BLOCKED / ERROR."""
    for line in reversed((out or "").splitlines()):
        token = line.strip().split()[0] if line.strip() else ""
        if token in ("EXPLOITED", "BLOCKED"):
            return token
    return "ERROR"


def _python_phase(work: Path, spec: dict, version: str, scenario_dir: Path) -> dict:
    venv = work / ".venv"
    py = PYTHON.split()
    r = _run([*py, "-m", "venv", str(venv)], work)
    if r.returncode:
        return {"install": "fail", "detail": r.stderr[-400:]}
    vpy = venv / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    offline = ["--no-index", "--find-links", str(VENDOR)] if VENDOR.exists() else []
    r = _run([str(vpy), "-m", "pip", "install", "-q", *offline, f"{spec['package']}=={version}"], work)
    if r.returncode:
        return {"install": "fail", "detail": (r.stderr or r.stdout)[-400:]}
    shutil.copy(_asset(scenario_dir, spec["attack"]), work / spec["attack"])
    atk = _run([str(vpy), spec["attack"]], work)
    phase = {"install": version, "attack": _verdict(atk.stdout), "attack_raw": atk.stdout.strip()[-200:]}
    if spec.get("test"):
        shutil.copy(_asset(scenario_dir, spec["test"]), work / spec["test"])
        t = _run([str(vpy), spec["test"]], work)
        phase["test"] = "pass" if t.returncode == 0 else "fail"
    return phase


def _node_phase(work: Path, spec: dict, version: str, scenario_dir: Path) -> dict:
    pkg = spec["package"]
    tgz = next(iter(VENDOR.glob(f"{pkg}-{version}.tgz")), None) if VENDOR.exists() else None
    target = str(tgz) if tgz else f"{pkg}@{version}"
    offline = ["--offline"] if tgz else []
    (work / "package.json").write_text('{"name":"sandbox","private":true}', encoding="utf-8")
    r = _run([NPM, "i", "--no-audit", "--no-fund", "--silent", *offline, target], work)
    if r.returncode:
        return {"install": "fail", "detail": (r.stderr or r.stdout)[-400:]}
    shutil.copy(_asset(scenario_dir, spec["attack"]), work / spec["attack"])
    atk = _run([NODE, spec["attack"]], work)
    phase = {"install": version, "attack": _verdict(atk.stdout), "attack_raw": atk.stdout.strip()[-200:]}
    if spec.get("test"):
        shutil.copy(_asset(scenario_dir, spec["test"]), work / spec["test"])
        t = _run([NODE, spec["test"]], work)
        phase["test"] = "pass" if t.returncode == 0 else "fail"
    return phase


SANDBOX_IMAGE = {"PyPI": os.environ.get("SENTINEL_SANDBOX_IMAGE_PY", "dep-sentinel-sandbox-py:0.1"),
                 "npm": os.environ.get("SENTINEL_SANDBOX_IMAGE_NODE", "dep-sentinel-sandbox-node:0.1")}


def _docker_phase(scenario_dir: Path, spec: dict, version: str) -> dict:
    """Run one phase inside `docker run --network none`: real isolation, no network."""
    env = ["-e", f"PKG={spec['package']}", "-e", f"VERSION={version}", "-e", f"ATTACK={spec['attack']}"]
    if spec.get("test"):
        env += ["-e", f"TEST={spec['test']}"]
    cmd = ["docker", "run", "--rm", "--network", "none",
           "-v", f"{(scenario_dir / VERIFY_DIR).resolve()}:/verify:ro", *env, SANDBOX_IMAGE[spec["ecosystem"]]]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"install": "fail", "detail": (r.stderr or r.stdout)[-400:]}


def _backend(ecosystem: str) -> str:
    pref = os.environ.get("SENTINEL_SANDBOX_BACKEND")
    if pref:
        return pref
    try:
        if subprocess.run(["docker", "image", "inspect", SANDBOX_IMAGE[ecosystem]],
                          capture_output=True).returncode == 0:
            return "docker"
    except OSError:
        pass
    return "local"


def rehearse(scenario_dir: Path, spec: dict) -> dict:
    """Run the vulnerable then the fixed phase; classify the whole rehearsal."""
    backend = _backend(spec["ecosystem"])
    started = time.perf_counter()
    result = {"cve": spec.get("cve"), "package": spec["package"],
              "vulnerable_version": spec["vulnerable_version"], "fixed_version": spec["fixed_version"],
              "backend": "docker --network none" if backend == "docker" else "local",
              "phases": {}}
    for label, version in (("vulnerable", spec["vulnerable_version"]), ("fixed", spec["fixed_version"])):
        try:
            if backend == "docker":
                result["phases"][label] = _docker_phase(scenario_dir, spec, version)
            else:
                tmp = Path(tempfile.mkdtemp(prefix=f"sentinel-sb-{label}-"))
                try:
                    runner = _python_phase if spec["ecosystem"] == "PyPI" else _node_phase
                    result["phases"][label] = runner(tmp, spec, version, scenario_dir)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
        except subprocess.TimeoutExpired:
            result["phases"][label] = {"install": "timeout"}
    v, f = result["phases"]["vulnerable"], result["phases"]["fixed"]
    exp = spec.get("expect", {})
    proven = (v.get("attack") == exp.get("vulnerable", "EXPLOITED")
              and f.get("attack") == exp.get("fixed", "BLOCKED"))
    test_ok = f.get("test") in (None, "pass")
    result["fix_proven"] = bool(proven and test_ok)
    result["attack_before"] = v.get("attack")
    result["attack_after"] = f.get("attack")
    result["test_after"] = f.get("test", "n/a")
    result["seconds"] = round(time.perf_counter() - started, 1)
    return result


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    d = Path(sys.argv[1])
    spec = load_spec(d)
    if not spec:
        print("no verify.json in", d)
        sys.exit(1)
    print(json.dumps(rehearse(d, spec), ensure_ascii=False, indent=1))
