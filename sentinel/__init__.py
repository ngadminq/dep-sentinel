"""dep-sentinel: dependency security on-call — static tools decide, the LLM and Yuanbao search supply evidence."""

import os
from pathlib import Path

# Load ./.env for local runs (real environment variables win; Docker passes env_file instead).
_env = Path(__file__).resolve().parent.parent / ".env"
if _env.exists():
    for _line in _env.read_text(encoding="utf-8").splitlines():
        if "=" in _line and not _line.lstrip().startswith("#"):
            _k, _v = _line.split("=", 1)
            if _v.strip():
                os.environ.setdefault(_k.strip(), _v.strip())
