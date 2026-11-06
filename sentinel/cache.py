"""Record/replay cache for every external call (OSV, KEV, EPSS, Yuanbao, LLM).

Each call is stored as data/cache/<kind>/<sha>.json with the request and the raw
response, so a run can be replayed offline (SENTINEL_OFFLINE=1) and audited.
"""

import hashlib
import ipaddress
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener, urlopen

ROOT = Path(os.environ.get("SENTINEL_CACHE", Path(__file__).resolve().parent.parent / "data" / "cache"))
OFFLINE = os.environ.get("SENTINEL_OFFLINE") == "1"
STATS: dict[str, dict[str, int]] = {}


class OfflineMiss(RuntimeError):
    pass


def _key(kind: str, request: dict) -> Path:
    raw = json.dumps(request, ensure_ascii=False, sort_keys=True)
    return ROOT / kind / (hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20] + ".json")


def _count(kind: str, field: str) -> None:
    STATS.setdefault(kind, {"hit": 0, "live": 0})[field] += 1


def cached(kind: str, request: dict, fetch, ttl_hours: float | None = None) -> dict:
    """Return the cached record for request, calling fetch() only on a miss.

    ttl_hours: refresh feeds that change daily (KEV, EPSS) unless running offline.
    """
    path = _key(kind, request)
    if path.exists():
        stale = ttl_hours is not None and time.time() - path.stat().st_mtime > ttl_hours * 3600
        if OFFLINE or not stale:
            _count(kind, "hit")
            return json.loads(path.read_text(encoding="utf-8"))
    if OFFLINE:
        raise OfflineMiss(f"{kind} not cached: {json.dumps(request, ensure_ascii=False)[:120]}")
    started = time.perf_counter()
    response = fetch()
    record = {"request": request, "elapsed_ms": round((time.perf_counter() - started) * 1000),
              "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "response": response}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    _count(kind, "live")
    return record


def _private(url: str) -> bool:
    """Intranet model servers must bypass the corporate HTTP proxy."""
    try:
        ip = ipaddress.ip_address(urlsplit(url).hostname or "")
    except ValueError:
        return (urlsplit(url).hostname or "") in ("localhost", "host.docker.internal")
    return ip.is_private or ip.is_loopback


def http_json(url: str, body: dict | None = None, headers: dict | None = None, timeout: int = 60) -> dict:
    """POST (or GET when body is None) and decode JSON, retrying transient errors."""
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "User-Agent": "dep-sentinel/0.1"} | (headers or {})
    for attempt in range(3):
        try:
            req = Request(url, data=data, headers=hdrs, method="GET" if body is None else "POST")
            opener = build_opener(ProxyHandler({})).open if _private(url) else urlopen
            with opener(req, timeout=timeout) as r:
                return json.loads(r.read())
        except HTTPError as e:
            if e.code < 500 or attempt == 2:
                raise RuntimeError(f"HTTP {e.code} from {url}: {e.read()[:300]!r}") from e
        except (URLError, TimeoutError) as e:
            if attempt == 2:
                raise RuntimeError(f"{url}: {e}") from e
        time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


if __name__ == "__main__":     # python -m sentinel.cache FILE: print one recorded model call (question and answer)
    import re
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    rec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    msgs = rec["request"]["messages"]
    user = msgs[-1]["content"]
    m = re.search(r"用户原话：(.*)", user)
    answer = re.sub(r"<think>.*?</think>", "", rec["response"]["choices"][0]["message"]["content"], flags=re.S).strip()
    print(f"模型 {rec['request']['model']} · 记录时间 {rec['recorded_at']} · {rec['elapsed_ms']} ms")
    print(f"问题：{m.group(1) if m else user[:80]}")
    print("回答：")
    print(answer)
