#!/bin/sh
# 命令：
#   eval [--offline] [--modes osv static full]   跑内置 14 个验证场景 + 4 个群聊问答
#   scan /repos/* [--mode full] [--send]          扫描挂载进来的仓库，--send 推送钉钉
#   ask "群里转来的文字" [--repos /repos/*]        回答“我们有没有事”
#   fix /repos/* [--mode static]                  在隔离沙箱里预演修复，证明有效后生成补丁
#   patrol [--send]                               自动发现 /repos 下所有项目，只推送和上次相比的变化
#   watch                                         按 SCAN_INTERVAL 每天自动巡检 /repos 并推送
#   replay [--offline]                            回放 2026-01-01 至今每天巡检，对比漏洞库提醒次数
#   demo                                          离线跑一遍内置场景，打印钉钉消息样例
set -e

# 首次启动时把镜像内的录制数据铺到持久卷里（已存在的文件不覆盖）
if [ -d /opt/sentinel-cache ] && [ ! -f /data/cache/.seeded ]; then
  mkdir -p /data/cache && cp -rn /opt/sentinel-cache/. /data/cache/ 2>/dev/null || true
  touch /data/cache/.seeded
fi

cmd="${1:-help}"
[ $# -gt 0 ] && shift

case "$cmd" in
  eval)
    if [ "$1" = "--offline" ]; then
      # 回放录制数据：模型名决定缓存键，地址不会被访问
      export SENTINEL_OFFLINE=1 LLM_MODEL="${LLM_MODEL:-Qwen3.8-27B-FP8}" LLM_BASE_URL="${LLM_BASE_URL:-http://offline.invalid/v1}"
      shift
    fi
    exec python eval.py --out /out/eval "$@"
    ;;
  scan)
    exec python -m sentinel scan --out /out/scan "$@"
    ;;
  ask)
    q="$1"; shift
    if [ $# -eq 0 ]; then set -- --repos /repos/*; fi
    exec python -m sentinel ask "$q" "$@"
    ;;
  watch)
    interval="${SCAN_INTERVAL:-86400}"
    while true; do
      echo "[$(date '+%F %T')] 开始巡检 /repos"
      python -m sentinel patrol /repos --send || echo "本轮巡检失败，稍后重试"
      sleep "$interval"
    done
    ;;
  patrol)
    exec python -m sentinel patrol /repos "$@"
    ;;
  fix)
    # 沙箱预演需要在装了 docker 的宿主/CI 上跑，由它拉起隔离的 dep-sentinel-sandbox 容器
    exec python -m sentinel fix --out /out/fixes "$@"
    ;;
  replay)
    if [ "$1" = "--offline" ]; then
      export SENTINEL_OFFLINE=1 LLM_MODEL="${LLM_MODEL:-Qwen3.8-27B-FP8}" LLM_BASE_URL="${LLM_BASE_URL:-http://offline.invalid/v1}"
      shift
    fi
    mkdir -p /out
    exec python replay.py --out /out/replay.json "$@"
    ;;
  demo)
    export SENTINEL_OFFLINE=1
    exec python -m sentinel scan scenarios/s01-log4shell scenarios/s09-axios-noise scenarios/s04-lodash-reachable \
      --mode "${DEMO_MODE:-static}" --out /out/demo
    ;;
  *)
    sed -n '2,9p' "$0"
    ;;
esac
