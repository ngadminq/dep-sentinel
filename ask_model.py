"""Ask the configured model a question with no search results attached (used for the "model alone" comparison).

  python ask_model.py "问题"
"""

import json
import re
import sys
import time

from sentinel import llm  # noqa: F401  (loads .env)
from sentinel.cache import http_json
import os

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    q = sys.argv[1]
    body = {"model": os.environ["LLM_MODEL"], "temperature": 0.2, "messages": [{"role": "user", "content": q}]}
    t = time.time()
    r = http_json(os.environ["LLM_BASE_URL"].rstrip("/") + "/chat/completions", body, {}, 180)
    text = re.sub(r"<think>.*?</think>", "", r["choices"][0]["message"]["content"], flags=re.S).strip()
    print(f"[{os.environ['LLM_MODEL']}，没有搜索结果，{time.time() - t:.1f} 秒]")
    print(text)
