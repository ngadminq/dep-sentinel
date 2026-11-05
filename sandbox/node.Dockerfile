# 沙箱镜像（npm 生态）：包在编排机上预取好，构建只 COPY，运行时 --network none 离线装。
FROM node:18-slim
COPY vendor/ /opt/vendor/
COPY run_phase.js /opt/run_phase.js
ENV TZ=Asia/Shanghai
ENTRYPOINT ["node", "/opt/run_phase.js"]
