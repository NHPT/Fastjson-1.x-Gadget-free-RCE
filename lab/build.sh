#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[*] Fastjson 1.2.83 RCE Lab 构建脚本"
echo ""
echo "  方式一: GitHub Actions（推荐，无需本地 Maven）"
echo "    1. 推送到 GitHub 仓库"
echo "    2. Actions 自动构建并提交 lab/app.jar 到仓库"
echo "    3. git pull 获取最新 JAR"
echo "    4. docker-compose up -d --build"
echo ""
echo "  方式二: 本地 Maven 构建"
echo "    mvn -q -DskipTests clean package && cp target/fastjson-rce-lab-1.0.0.jar app.jar"
echo ""

mvn -q -DskipTests clean package
cp target/fastjson-rce-lab-1.0.0.jar app.jar
echo "[+] Build complete: app.jar"
echo ""
echo "启动容器:"
echo "  docker-compose up -d --build"
echo ""
echo "验证:"
echo "  curl http://localhost:18080/info"