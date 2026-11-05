"""One sandbox phase, run inside the isolated container (python 3.9, stdlib only).

Installs ONE version of a package from the baked-in vendor directory (no network),
runs the mounted attack script, optionally the smoke test, and prints a JSON verdict.
The orchestrator calls this twice per fix: once for the vulnerable version, once for
the fixed one. Everything runs under `docker run --network none`.

env: ECOSYSTEM PyPI|npm, PKG, VERSION, ATTACK (file in /verify), TEST (optional)
"""

import glob
import json
import os
import subprocess
import sys
import tempfile

VENDOR = "/opt/vendor"
VERIFY = "/verify"
TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "180"))


def run(cmd, cwd, env=None):
    full = dict(os.environ)
    if env:
        full.update(env)
    return subprocess.run(cmd, cwd=cwd, env=full, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=TIMEOUT)


def verdict(out):
    for line in reversed((out or "").splitlines()):
        head = line.strip().split(" ")[0] if line.strip() else ""
        if head in ("EXPLOITED", "BLOCKED"):
            return head
    return "ERROR"


def py_phase(work, pkg, version, attack, test):
    r = run([sys.executable, "-m", "pip", "install", "-q", "--no-index",
             "--find-links", VENDOR, pkg + "==" + version], work)
    if r.returncode:
        return {"install": "fail", "detail": r.stdout.decode("utf-8", "ignore")[-300:]}
    res = {"install": version}
    a = run([sys.executable, os.path.join(VERIFY, attack)], work)
    res["attack"] = verdict(a.stdout.decode("utf-8", "ignore"))
    res["attack_raw"] = a.stdout.decode("utf-8", "ignore").strip()[-200:]
    if test:
        t = run([sys.executable, os.path.join(VERIFY, test)], work)
        res["test"] = "pass" if t.returncode == 0 else "fail"
    return res


def node_phase(work, pkg, version, attack, test):
    tgz = glob.glob(os.path.join(VENDOR, pkg + "-" + version + ".tgz"))
    target = tgz[0] if tgz else (pkg + "@" + version)
    with open(os.path.join(work, "package.json"), "w") as fh:
        fh.write('{"name":"sb","private":true}')
    r = run(["npm", "i", "--offline", "--no-audit", "--no-fund", "--silent", target], work)
    if r.returncode:
        return {"install": "fail", "detail": r.stdout.decode("utf-8", "ignore")[-300:]}
    res = {"install": version}
    a = run(["node", os.path.join(VERIFY, attack)], work)
    res["attack"] = verdict(a.stdout.decode("utf-8", "ignore"))
    res["attack_raw"] = a.stdout.decode("utf-8", "ignore").strip()[-200:]
    if test:
        t = run(["node", os.path.join(VERIFY, test)], work)
        res["test"] = "pass" if t.returncode == 0 else "fail"
    return res


def main():
    eco = os.environ["ECOSYSTEM"]
    work = tempfile.mkdtemp(prefix="phase-")
    fn = py_phase if eco == "PyPI" else node_phase
    out = fn(work, os.environ["PKG"], os.environ["VERSION"],
             os.environ["ATTACK"], os.environ.get("TEST") or None)
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
