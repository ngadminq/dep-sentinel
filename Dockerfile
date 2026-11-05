# dep-sentinel：依赖安全值班员（动静结合：确定性工具 + 大模型 + 元宝搜索）
# 只用 Python 标准库，镜像里不装任何第三方 pip 包。
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_CACHE=/data/cache \
    TZ=Asia/Shanghai

WORKDIR /app
COPY sentinel/ sentinel/
COPY eval.py replay.py docker-entrypoint.sh ./
COPY scenarios/ scenarios/
# 录制好的调用记录：不配任何密钥也能离线复现全部实验
COPY data/cache/ /opt/sentinel-cache/

# 在 Windows 上检出的脚本可能是 CRLF 换行，先统一成 LF
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh \
    && useradd --create-home --uid 10001 sentinel \
    && mkdir -p /data /repos /out && chown -R sentinel /data /repos /out
USER sentinel

VOLUME ["/data", "/out"]
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["help"]
