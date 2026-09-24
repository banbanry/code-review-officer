#!/usr/bin/env python3
"""
本地核心规则匹配器（白盒 fallback）

当 Semgrep / bandit / cppcheck 挂了时，用这个脚本跑最核心的规则。
每条规则都是白盒写死的正则/AST 匹配，知道在查什么。

用法：
  python local_rules.py <文件或目录> [--json]
"""

import re
import sys
import json
from pathlib import Path


# ========== C 语言规则 ==========

C_RULES = [
    {
        "id": "C-002",
        "severity": "p0",
        "category": "BUFFER_OVERFLOW",
        "name": "缓冲区溢出",
        "pattern": r'\bstrcpy\s*\(',
        "message": "使用了不安全的 strcpy，建议换成 strncpy",
    },
    {
        "id": "C-001",
        "severity": "p0",
        "category": "NULL_DEREF",
        "name": "空指针解引用",
        # 简化版：找 malloc 后面没跟 if NULL 的（粗略匹配）
        "pattern": r'malloc\s*\([^)]+\)\s*;',
        "message": "malloc 返回值可能没检查 NULL，请确认后面有判空",
    },
    {
        "id": "C-008",
        "severity": "p0",
        "category": "DIV_ZERO",
        "name": "除零风险",
        "pattern": r'/\s*[a-zA-Z_]\w*\s*;',
        "message": "除法运算请确认除数不为 0",
    },
    {
        "id": "C-005",
        "severity": "p1",
        "category": "INTEGER_UNDERFLOW",
        "name": "无符号下溢风险",
        "pattern": r'uint8_t\s+\w+\s*;\s*.*\w+--',
        "message": "uint8_t 递减可能下溢 wrap，请确认 >0 才减",
    },
]


# ========== Python 规则 ==========

PY_RULES = [
    {
        "id": "P-003",
        "severity": "p1",
        "category": "HARDCODED_SECRET",
        "name": "硬编码密钥",
        "pattern": r'(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{30,})',
        "message": "检测到硬编码 API key/token，请移到环境变量",
    },
    {
        "id": "P-005",
        "severity": "p1",
        "category": "SILENT_EXCEPT",
        "name": "静默吞错",
        "pattern": r'except\s+Exception\s*:\s*pass',
        "message": "except Exception: pass 会静默吞掉错误，至少加个日志",
    },
    {
        "id": "P-001",
        "severity": "p0",
        "category": "CODE_INJECTION",
        "name": "代码注入",
        "pattern": r'\beval\s*\(',
        "message": "eval() 有代码注入风险，建议用 ast.literal_eval",
    },
    {
        "id": "P-007",
        "severity": "p2",
        "category": "MUTABLE_DEFAULT",
        "name": "可变默认参数",
        "pattern": r'def\s+\w+\s*\([^)]*=\s*\[\s*\]',
        "message": "默认参数 [] 是可变的，所有调用会共享，建议用 None",
    },
]


def scan_file(filepath: str) -> list:
    """扫描单个文件，返回发现列表"""
    findings = []
    ext = Path(filepath).suffix

    # 选规则集
    if ext in ('.c', '.h', '.cpp', '.hpp'):
        rules = C_RULES
    elif ext == '.py':
        rules = PY_RULES
    else:
        return findings

    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):
        for rule in rules:
            if re.search(rule["pattern"], line):
                findings.append({
                    "layer": "LOCAL-RULES",
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "file": filepath,
                    "line": i,
                    "message": f'[{rule["id"]}] {rule["name"]}: {rule["message"]}',
                })

    return findings


def scan_target(target: str) -> list:
    """扫描文件或目录"""
    all_findings = []

    if Path(target).is_file():
        all_findings.extend(scan_file(target))
    elif Path(target).is_dir():
        for ext in ('*.c', '*.h', '*.py'):
            for f in Path(target).rglob(ext):
                all_findings.extend(scan_file(str(f)))

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python local_rules.py <文件或目录> [--json]")
        sys.exit(1)

    target = sys.argv[1]
    as_json = "--json" in sys.argv

    findings = scan_target(target)

    if as_json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
    else:
        print(f"本地规则扫描：共 {len(findings)} 个发现")
        print("-" * 60)
        for f in findings:
            print(f'[{f["severity"].upper()}] {f["file"]}:{f["line"]}')
            print(f'  {f["message"]}')
            print()
