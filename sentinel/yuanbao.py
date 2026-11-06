"""Yuanbao SearchPro: the agent's only window onto live, unstructured intelligence."""

import json
import os
import re

from .cache import cached, http_json

ENDPOINT = "https://api.wsa.cloud.tencent.com/SearchPro"


def clean_query(text: str) -> str:
    """Strip exploit payloads and URLs before searching.

    A forwarded Log4Shell alert contains `${jndi:ldap://...}`; sent verbatim, the
    gateway's WAF (rightly) treats the search request itself as an attack.
    """
    text = re.sub(r"\$\{[^}]*\}?", " ", text)
    text = re.sub(r"\w+://\S+", " ", text)
    text = re.sub(r"[<>{}$`\\|;]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def safe_search(query: str, **kw) -> dict:
    """search() that degrades to "no results" instead of failing the whole run."""
    try:
        return search(clean_query(query), **kw)
    except Exception as e:  # noqa: BLE001 - any search failure must not stop triage
        return {"request_id": None, "query": {"Query": clean_query(query)}, "pages": [], "error": str(e)[:200]}


def search(query: str, freshness: str = "", cnt: str = "10", industry: str = "") -> dict:
    """Return {"request_id", "pages": [...]} for one SearchPro call (cached)."""
    params = {"Query": query[:120], "Cnt": cnt}
    if freshness:
        params["Freshness"] = freshness
    if industry:
        params["Industry"] = industry

    def fetch() -> dict:
        key = os.environ.get("YUANBAO_API_KEY", "").strip()
        if not key:
            raise RuntimeError("YUANBAO_API_KEY 未设置")
        return http_json(ENDPOINT, params, {"Authorization": "Bearer " + key})

    rec = cached("yuanbao", params, fetch)
    root = rec["response"].get("Response", rec["response"])
    if root.get("Error"):
        raise RuntimeError(f"Yuanbao error: {root['Error']}")
    pages = []
    for item in root.get("Pages", []):
        p = json.loads(item) if isinstance(item, str) else item
        pages.append({"title": p.get("title", ""), "url": p.get("url", ""), "site": p.get("site", ""),
                      "date": p.get("date", ""), "content": (p.get("content") or p.get("passage") or "")[:1800]})
    return {"request_id": root.get("RequestId"), "query": params, "pages": pages}


if __name__ == "__main__":     # python -m sentinel.yuanbao "查询词": show one SearchPro call as it was recorded
    import sys
    from .cache import _key
    sys.stdout.reconfigure(encoding="utf-8")
    q = clean_query(sys.argv[1])
    res = search(q)
    rec = json.loads(_key("yuanbao", res["query"]).read_text(encoding="utf-8"))
    print(f"POST {ENDPOINT}")
    print("Authorization: Bearer ****（已打码）")
    print(json.dumps(res["query"], ensure_ascii=False))
    print(f"RequestId: {res['request_id']}    记录时间: {rec.get('recorded_at', '')}")
    for i, p in enumerate(res["pages"][:4]):
        print(f"[{i}] {p['site'] or p['url'].split('/')[2]} · {p['date'][:10]}")
        print(f"    {p['title'][:60]}")
