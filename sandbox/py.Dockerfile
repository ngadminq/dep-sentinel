# 沙箱镜像（Python 生态）：包在编排机上预取好，构建只 COPY，运行时 --network none 离线装。
FROM python:3.8-slim
COPY vendor/ /opt/vendor/
COPY run_phase.py /opt/run_phase.py
ENV PYTHONUNBUFFERED=1 TZ=Asia/Shanghai
ENTRYPOINT ["python3", "/opt/run_phase.py"]
