"""Group OSV CWE ids into a handful of plain-language vulnerability types (for reports and the article)."""

# first matching group wins, so the more dangerous types come first
GROUPS = [
    ("恶意包", {"CWE-506", "CWE-829"}),
    ("远程代码执行 / 注入", {"CWE-94", "CWE-77", "CWE-78", "CWE-917", "CWE-502", "CWE-1336", "CWE-74"}),
    ("原型污染", {"CWE-1321", "CWE-915"}),
    ("SSRF", {"CWE-918", "CWE-441"}),
    ("XSS / 头部注入", {"CWE-79", "CWE-116", "CWE-93", "CWE-113"}),
    ("拒绝服务", {"CWE-400", "CWE-770", "CWE-1333", "CWE-674"}),
    ("信息泄露", {"CWE-200", "CWE-201", "CWE-524", "CWE-539"}),
]


def vuln_type(cwe_ids: list[str], malware: bool = False) -> str:
    ids = set(cwe_ids or [])
    if malware:
        return "恶意包"
    for name, group in GROUPS:
        if ids & group:
            return name
    return "其他"
