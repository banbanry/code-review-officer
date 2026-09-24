#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 docx 提取 C/C++ 代码块，单独存成 .c/.h 文件"""

import os
import re
import zipfile
from xml.etree import ElementTree as ET

scan_dir = r"D:\WorkBuddy\code-review-officer\test_targets\multi_source_c_20260924"
os.makedirs(scan_dir, exist_ok=True)

files = [
    ("光芯片保护器", r"D:\WorkBuddy\PEFMOD\原始素材\614整批\05-非厄密拓扑与光芯片\光芯片保护器基础源码1.0.docx"),
    ("探三元芯片", r"D:\WorkBuddy\PEFMOD\_垃圾隔离区\PEF资料库\06-专利与软著\524\探三元芯片源码2.0.docx"),
    ("异构B防火墙", r"D:\WorkBuddy\PEFMOD\原始素材\524\00-救援设计语料\源码与固件\异构b源码修复过程历史.docx"),
    ("HSM安全监控", r"D:\能用\hsm项目\HSM源码.docx"),
    ("探探防火墙B5", r"D:\迁移文件夹\b\探探防火墙B款 修订版本5.0_完整说明与源码.txt"),
    ("重构B源码", r"D:\迁移文件夹\b\重构b源码.docx"),
    ("经典B款mod3", r"D:\slu\历史\经典B款探探防火墙源码mod3_202603251716_13282.docx"),
]

def extract_from_docx(path):
    try:
        with zipfile.ZipFile(path, 'r') as z:
            with z.open('word/document.xml') as f:
                xml_content = f.read().decode('utf-8')
        root = ET.fromstring(xml_content)
        paragraphs = []
        for p in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
            texts = []
            for t in p.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t'):
                if t.text:
                    texts.append(t.text)
            paragraphs.append(''.join(texts))
        return '\n'.join(paragraphs)
    except Exception as e:
        return f"# 提取失败: {e}"

def extract_from_txt(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def extract_code_blocks(text):
    """提取 ```c ... ``` 或 ```cpp ... ``` 代码块"""
    blocks = []
    # 匹配 ```c / ```cpp / ```c++ 开头的代码块
    pattern = r'```(?:c|cpp|c\+\+|objective-c)?\n(.*?)```'
    for m in re.finditer(pattern, text, re.DOTALL):
        code = m.group(1)
        # 简单判断：如果代码里有 #include 或 #ifndef 或 typedef，就是 C 代码
        if '#include' in code or '#ifndef' in code or 'typedef' in code or 'uint8_t' in code:
            blocks.append(code)
    return blocks

# 处理每个文件
total_files = 0
total_lines = 0

for name, path in files:
    print(f"处理: {name}")
    
    if path.endswith('.docx'):
        content = extract_from_docx(path)
    else:
        content = extract_from_txt(path)
    
    # 提取 C 代码块
    code_blocks = extract_code_blocks(content)
    
    if not code_blocks:
        print(f"  -> 未找到 C 代码块")
        continue
    
    # 每个代码块存成一个 .c 文件
    for i, code in enumerate(code_blocks):
        safe_name = re.sub(r'[^\w]', '_', name)
        out_path = os.path.join(scan_dir, f"{safe_name}_part{i+1}.c")
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(f"// Source: {name} (part {i+1})\n\n")
            f.write(code)
        
        lines = code.count('\n') + 1
        total_files += 1
        total_lines += lines
    
    print(f"  -> 提取 {len(code_blocks)} 个 C 代码块")

print(f"\n完成: 共 {total_files} 个 .c 文件, {total_lines} 行代码")
