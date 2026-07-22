# ============================================================
# Fastjson 1.2.83 @JSONType RCE Lab - 受害者容器
# ============================================================
# app.jar 由 GitHub Actions 自动构建并提交到仓库
# 用户只需 git pull → docker-compose up -d --build
# ============================================================

FROM eclipse-temurin:8-jre-slim

WORKDIR /app
COPY app.jar /app/app.jar

EXPOSE 18080
USER 10001
ENTRYPOINT ["java", "-Djava.net.useSystemProxies=false", "-jar", "/app/app.jar"]