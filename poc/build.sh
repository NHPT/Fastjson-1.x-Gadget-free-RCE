#!/usr/bin/env bash
set -euo pipefail

# Fastjson 1.2.83 @JSONType RCE PoC 构建脚本
# 编译 GenProbe.java 并打包为 poc/probe（文件内容是 JAR，无 .jar 后缀）
#
# 前置条件:
#   1. JDK 已安装（JDK 8 或可编译 Java 8 字节码的新版 JDK）
#   2. Python 3 已安装
#
# 也可使用 GitHub Actions 构建:
#   推送到 GitHub → Actions → Build JARs → 拉取 poc/probe

cd "$(dirname "$0")"

python3 serve.py --build-only --force-build "$@"
