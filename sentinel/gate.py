"""Static step 4: the evidence gate. Plain rules decide the level; the LLM only supplies inputs.

RED    今天修   malware, or reachable + exploitation signal, or KEV-listed and in use
YELLOW 本周     affected version in production code, no exploitation signal or not proven reachable
WHITE  记录     dev/test-only, or declared but never imported
"""

EPSS_HOT = 0.1          # >= 10% predicted exploitation probability within 30 days
MIN_DOMAINS = 2         # web evidence counts only when two independent sites agree

RED, YELLOW, WHITE = "red", "yellow", "white"


def exploitation(v: dict, card: dict | None) -> dict:
    domains = sorted({e["domain"] for e in (card or {}).get("exploit_evidence", [])})
    signals = []
    if v.get("kev"):
        signals.append("CISA KEV 已收录（确认在野利用）")
    if v.get("epss", 0) >= EPSS_HOT:
        signals.append(f"EPSS {v['epss']:.2f}（30 天内被利用概率高）")
    if len(domains) >= MIN_DOMAINS:
        signals.append(f"{len(domains)} 个独立来源报道利用/PoC")
    return {"hot": bool(signals), "signals": signals, "web_domains": domains}


def decide(f: dict) -> dict:
    """f: one finding (package x vulnerability) with static + dynamic facts attached."""
    pkg, v, card, reach = f["package"], f["vuln"], f.get("card"), f.get("reach", {})
    exp = exploitation(v, card)
    imported = bool(f.get("import_hits")) or not pkg.direct or pkg.ecosystem == "runtime"
    r = reach.get("reachable", "unknown")

    if v.get("malware"):
        return _out(RED, "恶意包：安装即可能执行恶意代码，与是否调用无关", "affected", exp)
    if pkg.dev:
        return _out(WHITE, "仅开发/测试依赖，不随生产代码发布", "not_affected", exp,
                    "vulnerable_code_not_in_execute_path")
    if not imported:
        return _out(WHITE, "依赖已声明，但源码中没有任何引用", "not_affected", exp, "vulnerable_code_not_present")
    if v.get("kev") and r != "no":
        return _out(RED, "CISA 已确认在野利用，且代码在使用该组件", "affected", exp)
    if r == "yes" and exp["hot"]:
        return _out(RED, "代码调用了漏洞函数，且存在利用信号", "affected", exp)
    if r == "yes":
        return _out(YELLOW, "代码调用了漏洞函数，暂无利用信号", "affected", exp)
    if r in ("no", "no-static"):
        why = "静态检索未发现漏洞函数调用" if r == "no-static" else "调用存在但判定外部输入不可控"
        return _out(YELLOW, why + "，疑似不受影响，需人工确认", "under_investigation", exp)
    if exp["hot"]:
        return _out(YELLOW, "组件在用且有利用信号，但无法定位具体漏洞函数", "under_investigation", exp)
    return _out(YELLOW, "受影响版本在用，暂无利用信号", "under_investigation", exp)


def _out(level: str, reason: str, vex: str, exp: dict, justification: str = "") -> dict:
    return {"level": level, "reason": reason, "vex_status": vex, "vex_justification": justification,
            "exploitation": exp}
