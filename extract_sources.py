#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 docx/txt 提取源码，保存为 .py 文件用于扫描"""

import os
import re
from pathlib import Path

scan_dir = r"D:\WorkBuddy\code-review-officer\test_targets\multi_source_20260924"
os.makedirs(scan_dir, exist_ok=True)

# 文件列表
files = [
    ("光芯片保护器源码1.0", r"D:\WorkBuddy\PEFMOD\原始素材\614整批\05-非厄密拓扑与光芯片\光芯片保护器基础源码1.0.docx"),
    ("探三元芯片源码2.0", r"D:\WorkBuddy\PEFMOD\_垃圾隔离区\PEF资料库\06-专利与软著\524\探三元芯片源码2.0.docx"),
    ("异构B源码修复历史", r"D:\WorkBuddy\PEFMOD\原始素材\524\00-救援设计语料\源码与固件\异构b源码修复过程历史.docx"),
    ("HSM源码", r"D:\能用\hsm项目\HSM源码.docx"),
    ("探探防火墙B款5.0", r"D:\迁移文件夹\b\探探防火墙B款 修订版本5.0_完整说明与源码.txt"),
    ("重构B源码", r"D:\迁移文件夹\b\重构b源码.docx"),
    ("探三元芯片历史版", r"D:\slu\历史\探三元芯片源码2.0.docx"),
    ("经典B款防火墙mod3", r"D:\slu\历史\经典B款探探防火墙源码mod3_202603251716_13282.docx"),
]

def extract_from_docx(path):
    """从 docx 提取文本"""
    try:
        from docx import Document
        doc = Document(path)
        text = "\n".join([p.text for p in doc.paragraphs])
        return text
    except Exception as e:
        return f"# 提取失败: {e}"

def extract_from_txt(path):
    """从 txt 提取文本"""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def find_code_blocks(text):
    """尝试提取代码块"""
    # 找 ```python ... ``` 或 ``` ... ```
    blocks = re.findall(r'```(?:python)?\n(.*?)```', text, re.DOTALL)
    if blocks:
        return "\n\n# ===== 代码块分隔 =====\n\n".join(blocks)
    # 没有代码块标记，就用全文
    return text

# 处理每个文件
for name, path in files:
    print(f"处理: {name}")
    
    if path.endswith('.docx'):
        content = extract_from_docx(path)
    else:
        content = extract_from_txt(path)
    
    # 提取代码块
    code = find_code_blocks(content)
    
    # 保存为 .py 文件
    safe_name = re.sub(r'[^\w]', '_', name)
    out_path = os.path.join(scan_dir, f"{safe_name}.py")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(f"# Source: {name}\n# File: {os.path.basename(path)}\n\n")
        f.write(code)
    
    lines = code.count('\n') + 1
    size = len(code) / 1024
    print(f"  -> {out_path} ({lines} 行, {size:.1f} KB)")

print(f"\n完成，共 {len(files)} 个文件")
