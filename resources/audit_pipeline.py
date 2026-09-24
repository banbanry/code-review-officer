#!/usr/bin/env python3
"""
PEF 多层代码审查工作流编排器
组合开源静态分析工具 + CLE 物理不变量探针，输出统一审查报告。

层级设计：
  L0 编译器粗筛  - gcc/clang -Wall -Wextra 编译警告（最基础过滤）
  L1 Semgrep     - 多语言通用静态分析（广度）
  L2 cppcheck    - C/C++ 专项深度扫描（语言专项）
  L3 bandit      - Python 专项安全扫描（语言专项）
  L4 gitleaks    - 密钥泄露扫描（安全基线）
  L5 trivy       - 依赖漏洞 + 配置扫描（供应链）
  L6 CLE 探针    - AI 幻觉 + 物理不变量检测（可信度）
  L7 冒烟测试    - 编译后运行，检测段错误/崩溃（运行时验证）
  L8 语义审查    - LLM 理解代码意图，判断逻辑正确性（语义级深度）
  L9 PEF 结构化  - P/E/F三元分解+因果链+七维评分+双闸门（确定性框架）

用法：
  python3 audit_pipeline.py <目标路径> [--output report.json] [--format json|text]

L8 语义审查环境变量：
  LLM_API_KEY    - API 密钥（必填，否则跳过 L8）
  LLM_BASE_URL   - API 地址（默认 https://api.deepseek.com/v1）
  LLM_MODEL      - 模型名（默认 deepseek-chat）
"""

import json
import os
import subprocess
import sys
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional


# ========== L8 后处理：去重 + 误报过滤 + 严重级校准 ==========

def l8_postprocess(findings: list) -> list:
    """L8 结果后处理：去重、过滤明显误报、校准严重级"""
    import re

    # 1. 过滤明显误报（太主观、没有实质问题的）
    false_positive_patterns = [
        r"命名.*不够.*好",
        r"建议.*加.*注释",
        r"可以.*优化.*可读性",
        r"代码.*风格.*不一致",
    ]
    filtered = []
    for f in findings:
        msg = f.get("message", "")
        is_fp = False
        for pat in false_positive_patterns:
            if re.search(pat, msg):
                is_fp = True
                break
        if not is_fp:
            filtered.append(f)

    # 2. 去重：同文件 + 同 category + 行号相差 < 3 行的合并
    deduped = []
    for f in filtered:
        is_dup = False
        for i, d in enumerate(deduped):
            if (f.get("file") == d.get("file") and
                f.get("category") == d.get("category") and
                abs(f.get("line", 0) - d.get("line", 0)) < 3):
                # 合并：保留严重级更高的那个
                sev_order = {"p0": 4, "p1": 3, "p2": 2, "p3": 1}
                if sev_order.get(f.get("severity", "p3"), 0) > sev_order.get(d.get("severity", "p3"), 0):
                    deduped[i] = f
                is_dup = True
                break
        if not is_dup:
            deduped.append(f)

    # 3. 严重级校准：统一标准
    # P0 必须是因果链完全断裂（崩溃级）
    for f in deduped:
        sev = f.get("severity", "p3").lower()
        cat = f.get("category", "")
        msg = f.get("message", "")

        # 如果标了 P0 但 category 不是崩溃级，降到 P1
        if sev == "p0":
            crash_categories = ["NULL_DEREF", "DIV_ZERO", "RACE_CONDITION", "TAINT_PROPAGATION", "USE_AFTER_FREE"]
            if not any(cc in cat.upper() for cc in crash_categories):
                # 再看 message 里有没有崩溃关键词
                if not any(kw in msg for kw in ["崩溃", "crash", "undefined behavior", "ub", "segfault"]):
                    f["severity"] = "p1"
                    f["severity_downgraded"] = True

    return deduped


# ========== 工具检测 ==========

def detect_tools() -> dict:
    """检测当前环境可用的审查工具"""
    tools = {}
    
    # L0 编译器（gcc/clang）
    if shutil.which("gcc"):
        tools["gcc"] = shutil.which("gcc")
    if shutil.which("clang"):
        tools["clang"] = shutil.which("clang")
    
    # Semgrep
    if shutil.which("semgrep"):
        tools["semgrep"] = shutil.which("semgrep")
    elif os.path.exists(os.path.expanduser("~/.local/bin/semgrep")):
        tools["semgrep"] = os.path.expanduser("~/.local/bin/semgrep")
    
    # cppcheck
    if shutil.which("cppcheck"):
        tools["cppcheck"] = shutil.which("cppcheck")
    
    # bandit
    if shutil.which("bandit"):
        tools["bandit"] = shutil.which("bandit")
    
    # gitleaks
    if shutil.which("gitleaks"):
        tools["gitleaks"] = shutil.which("gitleaks")
    else:
        for p in ["D:/tools/gitleaks/gitleaks.exe", "/tmp/gitleaks", os.path.expanduser("~/tools/gitleaks/gitleaks.exe")]:
            if os.path.exists(p):
                tools["gitleaks"] = p
                break

    # trivy
    if shutil.which("trivy"):
        tools["trivy"] = shutil.which("trivy")
    else:
        for p in ["D:/tools/trivy/trivy.exe", "/tmp/trivy", os.path.expanduser("~/tools/trivy/trivy.exe")]:
            if os.path.exists(p):
                tools["trivy"] = p
                break

    # CLE 探针（检测 skill 目录）
    cle_paths = [
        os.path.expanduser("~/.trae-cn/skills/cle-code-probe/resources/cle_deploy.py"),
        os.path.expanduser("~/.trae/skills/cle-code-probe/resources/cle_deploy.py"),
        os.path.expanduser("~/.doubao/agent_mode/workspace/.user_skills/cle-code-probe/resources/cle_deploy.py"),
        "/home/user/.doubao/agent_mode/workspace/.user_skills/cle-code-probe/resources/cle_deploy.py",
    ]
    for p in cle_paths:
        if os.path.exists(p):
            tools["cle_probe"] = p
            break
    
    # L9 PEF 结构化审查（检测 skill 目录）
    pef_paths = [
        os.path.expanduser("~/AppData/Local/Doubao/User Data/Default/.doubao/agent_mode/workspace/.user_skills/pef-structured-review/resources/pef_reviewer.py"),
        os.path.expanduser("~/.doubao/agent_mode/workspace/.user_skills/pef-structured-review/resources/pef_reviewer.py"),
        "/home/user/.doubao/agent_mode/workspace/.user_skills/pef-structured-review/resources/pef_reviewer.py",
    ]
    for p in pef_paths:
        if os.path.exists(p):
            tools["pef_review"] = p
            break
    
    
    # L8 增强：Open Code Review (ocr)
    if shutil.which("ocr"):
        tools["ocr"] = shutil.which("ocr")
    return tools


# ========== 各层扫描器 ==========

def run_compiler_check(target: str, compiler: str) -> dict:
    """L0: 编译器粗筛 - gcc/clang -Wall -Wextra 编译警告"""
    import tempfile, re
    findings = []
    try:
        c_files = []
        if os.path.isfile(target) and target.endswith((".c", ".cpp", ".cc", ".cxx")):
            c_files = [target]
        elif os.path.isdir(target):
            for ext in ("*.c", "*.cpp", "*.cc", "*.cxx"):
                c_files.extend(Path(target).rglob(ext))
        
        if not c_files:
            return {"status": "skipped", "findings": [], "count": 0, "reason": "无 C/C++ 文件"}
        
        output_bin = tempfile.mktemp()
        all_warnings = []
        
        for f in c_files[:10]:  # 限制最多 10 个文件
            result = subprocess.run(
                [compiler, "-Wall", "-Wextra", "-Wpedantic", "-fsyntax-only",
                 "-o", output_bin, str(f)],
                capture_output=True, text=True, timeout=60
            )
            # 解析警告/错误输出: file:line:col: warning: message
            for line in (result.stderr or "").splitlines():
                m = re.match(r'^(.+?):(\d+):(?:\d+:)?\s*(warning|error|note):\s*(.+)$', line)
                if m:
                    sev = m.group(3)
                    if sev == "error":
                        severity = "p0"
                    elif sev == "warning":
                        severity = "p1"
                    else:
                        continue  # 跳过 note
                    all_warnings.append({
                        "layer": "L0-Compiler",
                        "tool": compiler,
                        "file": m.group(1),
                        "line": int(m.group(2)),
                        "severity": severity,
                        "category": f"COMPILER_{sev.upper()}",
                        "message": m.group(4).strip(),
                    })
        
        findings = all_warnings
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_smoke_test(target: str, compiler: str) -> dict:
    """L7: 冒烟测试 - 多语言自适应（C/C++ 编译运行 + Python 导入检测）"""
    import tempfile
    findings = []
    try:
        # Python 项目冒烟测试：语法编译 + 关键模块导入
        if os.path.isdir(target) or (os.path.isfile(target) and target.endswith(".py")):
            return _run_python_smoke_test(target, findings)
        
        # C/C++ 单文件冒烟测试
        if not os.path.isfile(target) or not target.endswith((".c", ".cpp")):
            return {"status": "skipped", "findings": findings, "count": len(findings), "reason": "非支持的文件类型"}
        
        # 检查是否有 main 函数
        with open(target, "r", errors="ignore") as f:
            content = f.read()
        if "main(" not in content:
            return {"status": "skipped", "findings": findings, "count": len(findings), "reason": "无 main 函数，非可执行程序"}
        
        output_bin = tempfile.mktemp(suffix=".out")
        # 编译
        compile_result = subprocess.run(
            [compiler, "-o", output_bin, target],
            capture_output=True, text=True, timeout=60
        )
        if compile_result.returncode != 0:
            findings.append({
                "layer": "L7-Smoke",
                "tool": "smoke-test",
                "file": target,
                "line": 0,
                "severity": "p0",
                "category": "COMPILE_FAILED",
                "message": f"编译失败，无法进行冒烟测试: {compile_result.stderr[:200]}",
            })
            return {"status": "ok", "findings": findings, "count": len(findings)}
        
        # 运行（带超时，空输入）
        try:
            run_result = subprocess.run(
                [output_bin],
                capture_output=True, text=True, timeout=10,
                input=""
            )
            if run_result.returncode < 0:
                # 负返回码 = 被信号终止（段错误=11, 浮点异常=8 等）
                sig = -run_result.returncode
                findings.append({
                    "layer": "L7-Smoke",
                    "tool": "smoke-test",
                    "file": target,
                    "line": 0,
                    "severity": "p0",
                    "category": "RUNTIME_CRASH",
                    "message": f"运行时崩溃，被信号 {sig} 终止（段错误/浮点异常等）",
                    "signal": sig,
                })
            elif run_result.returncode != 0:
                findings.append({
                    "layer": "L7-Smoke",
                    "tool": "smoke-test",
                    "file": target,
                    "line": 0,
                    "severity": "p2",
                    "category": "NONZERO_EXIT",
                    "message": f"程序异常退出，返回码 {run_result.returncode}",
                })
            else:
                findings.append({
                    "layer": "L7-Smoke",
                    "tool": "smoke-test",
                    "file": target,
                    "line": 0,
                    "severity": "info",
                    "category": "SMOKE_PASS",
                    "message": "冒烟测试通过：编译成功，空输入运行正常退出",
                })
        except subprocess.TimeoutExpired:
            findings.append({
                "layer": "L7-Smoke",
                "tool": "smoke-test",
                "file": target,
                "line": 0,
                "severity": "p1",
                "category": "TIMEOUT",
                "message": "运行超时（10秒），可能存在死循环或阻塞",
            })
        finally:
            if os.path.exists(output_bin):
                os.remove(output_bin)
        
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}



def _run_python_smoke_test(target: str, findings: list) -> dict:
    """Python 冒烟测试：语法编译检查 + 入口脚本导入测试"""
    import py_compile
    import sys

    # 1. 收集 Python 文件
    py_files = []
    if os.path.isfile(target) and target.endswith(".py"):
        py_files = [target]
    elif os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', 'env', '__pycache__')]
            for f in files:
                if f.endswith('.py'):
                    py_files.append(os.path.join(root, f))
            if len(py_files) >= 20:
                break

    # 2. 语法编译检查
    syntax_errors = 0
    for f in py_files:
        try:
            py_compile.compile(f, doraise=True)
        except py_compile.PyCompileError as e:
            syntax_errors += 1
            findings.append({
                "layer": "L7-Smoke",
                "tool": "python-smoke",
                "file": f,
                "line": 0,
                "severity": "p0",
                "category": "SYNTAX_ERROR",
                "message": f"Python 语法错误: {str(e)[:200]}",
            })

    # 3. 入口脚本导入测试
    if os.path.isfile(target) and target.endswith(".py"):
        try:
            mod_name = os.path.basename(target)[:-3]
            sys.path.insert(0, os.path.dirname(target))
            __import__(mod_name)
            findings.append({
                "layer": "L7-Smoke",
                "tool": "python-smoke",
                "file": target,
                "line": 0,
                "severity": "info",
                "category": "IMPORT_OK",
                "message": f"模块 {mod_name} 导入成功，无语法/导入错误",
            })
        except ImportError as e:
            findings.append({
                "layer": "L7-Smoke",
                "tool": "python-smoke",
                "file": target,
                "line": 0,
                "severity": "p1",
                "category": "IMPORT_FAILED",
                "message": f"模块导入失败: {str(e)[:200]}",
            })
        except Exception as e:
            findings.append({
                "layer": "L7-Smoke",
                "tool": "python-smoke",
                "file": target,
                "line": 0,
                "severity": "p2",
                "category": "RUNTIME_IMPORT_ERROR",
                "message": f"导入时运行时错误: {type(e).__name__}: {str(e)[:150]}",
            })

    return {"status": "ok", "findings": findings, "count": len(findings),
            "py_files_checked": len(py_files), "syntax_errors": syntax_errors}

def run_local_rules(target: str) -> dict:
    """L1/L3 补充：本地白盒规则匹配（fallback 用）
    当 Semgrep/bandit 不可用时，用我们自己的规则保底。
    """
    try:
        import sys
        sys.path.insert(0, os.path.dirname(__file__))
        from local_rules import scan_target

        findings_raw = scan_target(target)
        findings = []
        for f in findings_raw:
            findings.append({
                "layer": "L1-LocalRules",
                "tool": "local-rules",
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "severity": f.get("severity", "p2"),
                "category": f.get("category", ""),
                "message": f.get("message", ""),
                "rule_id": f.get("rule_id", ""),
            })
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_semgrep(target: str, binary: str) -> dict:
    """L1: Semgrep 多语言静态分析"""
    try:
        result = subprocess.run(
            [binary, "scan", target, "--json", "--quiet", "--no-git-ignore"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode in (0, 1):
            data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
            findings = []
            for r in data.get("results", []):
                findings.append({
                    "layer": "L1-Semgrep",
                    "tool": "semgrep",
                    "file": r.get("path", ""),
                    "line": r.get("start", {}).get("line", 0),
                    "severity": r.get("extra", {}).get("severity", "INFO").lower(),
                    "category": r.get("check_id", ""),
                    "message": r.get("extra", {}).get("message", ""),
                    "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", ""),
                })
            return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}
    return {"status": "error", "findings": [], "error": "unknown"}


def run_cppcheck(target: str, binary: str) -> dict:
    """L2: cppcheck C/C++ 专项扫描"""
    try:
        result = subprocess.run(
            [binary, "--enable=all", "--inconclusive", "--xml", "--xml-version=2", target],
            capture_output=True, text=True, timeout=300
        )
        # 简化解析 XML
        findings = []
        import xml.etree.ElementTree as ET
        if result.stdout.strip():
            root = ET.fromstring(result.stdout)
            for error in root.iter("error"):
                findings.append({
                    "layer": "L2-cppcheck",
                    "tool": "cppcheck",
                    "file": error.get("file0", ""),
                    "line": int(error.get("line", 0)),
                    "severity": error.get("severity", "warning"),
                    "category": error.get("id", ""),
                    "message": error.get("msg", ""),
                    "cwe": error.get("cwe", ""),
                })
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_bandit(target: str, binary: str) -> dict:
    """L3: bandit Python 安全扫描"""
    try:
        result = subprocess.run(
            [binary, "-r", target, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode in (0, 1):
            data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
            findings = []
            for r in data.get("results", []):
                findings.append({
                    "layer": "L3-bandit",
                    "tool": "bandit",
                    "file": r.get("filename", ""),
                    "line": r.get("line_number", 0),
                    "severity": r.get("issue_severity", "LOW").lower(),
                    "category": r.get("test_id", ""),
                    "message": r.get("issue_text", ""),
                    "cwe": r.get("issue_cwe", {}).get("id", ""),
                })
            return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}
    return {"status": "error", "findings": [], "error": "unknown"}


def run_gitleaks(target: str, binary: str) -> dict:
    """L4: gitleaks 密钥泄露扫描"""
    import tempfile
    try:
        report_file = tempfile.mktemp(suffix=".json")
        result = subprocess.run(
            [binary, "detect", "--source", target, "--report-format", "json",
             "--report-path", report_file, "--no-banner", "--no-git"],
            capture_output=True, text=True, timeout=300
        )
        findings = []
        if os.path.exists(report_file):
            with open(report_file, "r") as f:
                content = f.read().strip()
                if content:
                    data = json.loads(content)
                    for r in data:
                        findings.append({
                            "layer": "L4-gitleaks",
                            "tool": "gitleaks",
                            "file": r.get("File", ""),
                            "line": r.get("StartLine", 0),
                            "severity": "critical",
                            "category": "SECRET_LEAK",
                            "message": f"检测到疑似密钥泄露: {r.get('RuleID', '')}",
                            "secret_type": r.get("RuleID", ""),
                            "entropy": r.get("Entropy", 0),
                        })
            os.remove(report_file)
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_trivy(target: str, binary: str) -> dict:
    """L5: trivy 依赖漏洞 + 配置扫描"""
    import tempfile
    try:
        report_file = tempfile.mktemp(suffix=".json")
        result = subprocess.run(
            [binary, "fs", "--scanners", "vuln,config,secret",
             "--format", "json", "--output", report_file,
             "--quiet", "--skip-db-update", target],
            capture_output=True, text=True, timeout=300
        )
        findings = []
        if os.path.exists(report_file):
            with open(report_file, "r") as f:
                content = f.read().strip()
                if content:
                    data = json.loads(content)
                    for result_item in data.get("Results", []):
                        target_file = result_item.get("Target", "")
                        # 漏洞
                        for vuln in result_item.get("Vulnerabilities", []):
                            severity = vuln.get("Severity", "UNKNOWN").lower()
                            sev_map = {"critical": "critical", "high": "p1", "medium": "p2", "low": "p3"}
                            findings.append({
                                "layer": "L5-trivy",
                                "tool": "trivy",
                                "file": target_file,
                                "line": 0,
                                "severity": sev_map.get(severity, "p2"),
                                "category": "DEPENDENCY_VULN",
                                "message": f"{vuln.get('VulnerabilityID','')}: {vuln.get('Title','')} (包: {vuln.get('PkgName','')} {vuln.get('InstalledVersion','')})",
                                "cve": vuln.get("VulnerabilityID", ""),
                                "fixed_version": vuln.get("FixedVersion", ""),
                            })
                        # 配置问题
                        for misconf in result_item.get("Misconfigurations", []):
                            findings.append({
                                "layer": "L5-trivy",
                                "tool": "trivy",
                                "file": target_file,
                                "line": misconf.get("CauseMetadata", {}).get("StartLine", 0),
                                "severity": misconf.get("Severity", "MEDIUM").lower(),
                                "category": "CONFIG_ISSUE",
                                "message": f"{misconf.get('Title','')}: {misconf.get('Description','')}",
                            })
            os.remove(report_file)
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_cle_probe(target: str, script: str) -> dict:
    """L6: CLE 物理不变量探针（AI 幻觉 + 运行时 bug）"""
    findings = []
    try:
        # 对 C/C++ 和 Python 文件运行 CLE audit
        files = []
        if os.path.isfile(target):
            if target.endswith((".c", ".cpp", ".h", ".hpp", ".py")):
                files = [target]
        elif os.path.isdir(target):
            for ext in ("*.c", "*.cpp", "*.h", "*.hpp", "*.py"):
                files.extend(Path(target).rglob(ext))
        
        for f in files[:30]:  # 限制最多 30 个文件
            result = subprocess.run(
                ["python", script, "audit", str(f)],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode in (0, 1) and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for finding in data.get("findings", []):
                        findings.append({
                            "layer": "L6-CLE-Probe",
                            "tool": "cle-code-probe",
                            "file": str(f),
                            "line": finding.get("line", 0),
                            "severity": finding.get("severity", "P1").lower(),
                            "category": finding.get("category", ""),
                            "message": finding.get("description", ""),
                            "causal_chain": finding.get("causal_chain", ""),
                            "event_id": finding.get("event_id", ""),
                            "confidence": finding.get("confidence", "LOW"),
                            "source": finding.get("source", ""),
                        })
                except json.JSONDecodeError:
                    pass
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_ocr_review(target: str, binary: str) -> dict:
    """L8 增强：Open Code Review (ocr) 行级精准审查
    依赖：git 仓库 + LLM 配置（OCR_LLM_URL 等）
    不可用时自动退回 Inline 模式
    """
    findings = []
    try:
        # ocr scan 是全文件扫描，不需要 git 仓库
        # 只要 ocr 二进制能跑就行（LLM key 已在 ocr 自己的 config 里）
        
        # 运行 ocr scan
        result = subprocess.run(
            [binary, "scan", "--path", target, "--format", "json"],
            capture_output=True, text=True, timeout=300, cwd=target
        )
        
        if result.returncode != 0:
            return {"status": "error", "findings": [], "error": f"ocr 退出码 {result.returncode}: {result.stderr[:200]}"}
        
        # 解析 JSON 输出
        data = json.loads(result.stdout)
        comments = data.get("comments", [])
        
        for c in comments:
            findings.append({
                "layer": "L8-ocr",
                "tool": "open-code-review",
                "file": c.get("file", ""),
                "line": c.get("line", 0),
                "severity": c.get("severity", "P2").lower(),
                "category": c.get("category", ""),
                "message": c.get("message", ""),
                "suggestion": c.get("suggestion", ""),
                "source": "ocr",
            })
        
        return {"status": "ok", "findings": findings, "count": len(findings)}
    
    except json.JSONDecodeError:
        return {"status": "error", "findings": [], "error": "ocr JSON 解析失败"}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_semantic_review(target: str) -> dict:
    """L8: LLM 语义审查 - 理解代码意图，判断逻辑正确性
    支持两种模式：
    - API 模式：设置 LLM_API_KEY 后自动调用外部 LLM
    - Inline 模式：无 API key 时输出审查上下文，由对话模型直接完成
    """
    api_key = os.environ.get("LLM_API_KEY", "")
    
    # 收集代码文件
    code_files = []
    if os.path.isfile(target):
        exts = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".py", ".js", ".ts", ".java", ".go", ".rs")
        if target.endswith(exts):
            code_files = [target]
    elif os.path.isdir(target):
        for ext in ("*.c", "*.cpp", "*.py", "*.js", "*.ts", "*.java", "*.go"):
            code_files.extend(Path(target).rglob(ext))
        code_files = [str(f) for f in code_files[:5]]
    
    if not code_files:
        return {"status": "skipped", "findings": [], "count": 0,
                "reason": "无可审查的代码文件"}
    
    # Inline 模式：输出审查上下文，由对话模型完成
    if not api_key:
        contexts = []
        for cf in code_files:
            with open(cf, "r", errors="ignore") as f:
                code = f.read()
            if len(code) > 8000:
                code = code[:8000] + "\n... (代码过长，已截断)"
            contexts.append({"file": cf, "code": code})
        
        prompt_template = """你是一个基于 PEF 第一性原理的代码审查专家。

## 审查框架：任何代码都是 P→E→F 三元结构

不管什么语言，剥开语法糖，本质都是：
- P 主体：谁在做？（函数/结构体/模块/状态机）
- E 变量：用什么做？（E_in 可控输入 + E_out 不可控输入）
- F 结果：做出了什么？（返回值/副作用/状态变化）

## 审查流程（五步）

### 第一步：P 主体分解
- 这个代码块的主体是什么？（函数名、类型、边界、单位）
- 主体的职责边界清晰吗？有没有越权？

### 第二步：E 变量分流
- E_in 可控输入：函数参数、配置项——有没有做边界校验？
- E_out 不可控输入：外部数据、硬件、网络——有没有防御策略？
- 有没有 E_in/E_out 混在一起的？

### 第三步：F 结果追溯
- 输出结果能不能追溯到 P 和 E？
- 有没有结果先于原因？有没有断裂的调用链？

### 第四步：因果链断裂检查（核心）
顺着 P→E→F 链条，逐条找断裂点：
- 输入有没有漏校验？
- 中间计算有没有溢出/下溢？
- 输出有没有不一致？
- 时序上有没有竞态？

## 各语言重点关注（按语言切换）

### C/C++ 代码重点
- malloc/free 配对：每个 malloc 有没有对应的 free？错误路径有没有释放？
- 缓冲区溢出：数组访问有没有边界检查？strcpy/strcat/sprintf 有没有换成安全版本？
- 指针空检查：malloc 返回值有没有检查？指针解引用前有没有判空？
- 整数溢出：有符号数运算会不会溢出？无符号数会不会下溢 wrap？

### Python 代码重点
- 危险函数：eval/exec/os.system/subprocess shell=True 有没有用户输入注入风险？
- 硬编码密钥：API key/密码/token 有没有写死在代码里？
- 异常处理：except Exception 是不是静默吞错？有没有加日志？
- 类型安全：有没有类型注解？有没有空值处理？

### 通用重点（所有语言）
- 边界条件：空值、极值、溢出有没有显式处理？
- 资源管理：文件句柄、内存、连接有没有正确释放？
- 时序因果：有没有结果先于原因？有没有断裂的调用链？

## 严重级评分
- P0：因果链完全断裂，崩溃级（空指针解引用、除零、竞态导致数据损坏）
- P1：因果链有缺口，高危（边界未校验、资源泄漏、错误处理缺失）
- P2：因果链不严谨，中危（命名混乱、规范偏差、可维护性差）
- P3：建议优化

## 输出格式
JSON 数组，每个问题包含：
- "severity": "P0"|"P1"|"P2"|"P3"
- "category": 问题类别（如 INPUT_NOT_VALIDATED / RACE_CONDITION / OVERFLOW_RISK / MEMORY_LEAK）
- "line": 行号（0表示整体）
- "message": 具体问题描述（要写清楚因果链：P[主体] → E[输入问题] → F[结果影响]）
- "suggestion": 修复建议

只输出 JSON 数组，没有问题输出 []。"""
        
        return {
            "status": "inline_pending",
            "findings": [],
            "count": 0,
            "reason": "Inline 模式：由对话模型完成语义审查",
            "inline_context": {
                "layer": "L8",
                "name": "LLM 语义审查",
                "prompt": prompt_template,
                "code_files": contexts,
                "expected_output": "JSON 数组，每项含 severity/category/line/message/suggestion",
            }
        }
    
    findings = []
    try:
        import urllib.request
        for cf in code_files:
            with open(cf, "r", errors="ignore") as f:
                code = f.read()
            if len(code) > 8000:
                code = code[:8000] + "\n... (代码过长，已截断)"
            
            prompt = f"""你是一个严格的代码审查专家，专门检测 AI 生成代码的幻觉和逻辑错误。

请审查以下代码，重点检查：
1. 逻辑错误：代码声称的功能与实际实现是否一致
2. AI 幻觉：空实现、假逻辑、TODO 占位、调用不存在的函数
3. 边界条件：输入验证、空值处理、溢出风险
4. 资源管理：内存泄漏、文件句柄未关闭
5. 不一致：函数签名与调用不匹配、返回值类型错误

代码文件：{cf}

```
{code}
```

请以 JSON 数组格式输出发现的问题，每个问题包含：
- "severity": "P0"|"P1"|"P2"|"P3"（P0=必须修复，P1=建议修复，P2=优化建议，P3=备注）
- "category": 问题类别（如 LOGIC_ERROR/AI_HALLUCINATION/BOUNDARY_MISSING/RESOURCE_LEAK/INCONSISTENCY）
- "line": 行号（0表示整体）
- "message": 具体问题描述
- "suggestion": 修复建议

只输出 JSON 数组，不要其他文字。如果没有问题，输出空数组 []。"""
            
            payload = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 2000,
            }).encode("utf-8")
            
            req = urllib.request.Request(
                f"{base_url}/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            
            content = result["choices"][0]["message"]["content"].strip()
            # 提取 JSON
            start = content.find("[")
            end = content.rfind("]") + 1
            if start >= 0 and end > start:
                issues = json.loads(content[start:end])
                for issue in issues:
                    findings.append({
                        "layer": "L8-Semantic",
                        "tool": f"llm:{model}",
                        "file": cf,
                        "line": issue.get("line", 0),
                        "severity": issue.get("severity", "P2").lower(),
                        "category": issue.get("category", "SEMANTIC"),
                        "message": issue.get("message", ""),
                        "suggestion": issue.get("suggestion", ""),
                    })
        
        # L8 后处理：去重 + 误报过滤 + 严重级校准
        findings = l8_postprocess(findings)
        return {"status": "ok", "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


def run_pef_review(target: str, script: str) -> dict:
    """L9: PEF 结构化审查 - P/E/F 三元分解 + 因果链 + 七维评分 + 双闸门
    支持两种模式：
    - API 模式：设置 LLM_API_KEY 后调用 pef_reviewer.py
    - Inline 模式：无 API key 时输出审查框架，由对话模型直接完成
    """
    # Inline 模式：输出审查框架，由对话模型完成
    if not os.environ.get("LLM_API_KEY", ""):
        # 只对单文件做 PEF 审查
        if not os.path.isfile(target):
            return {"status": "skipped", "findings": [], "count": 0,
                    "reason": "PEF 审查仅支持单文件"}
        
        with open(target, "r", errors="ignore") as f:
            code = f.read()
        if len(code) > 6000:
            code = code[:6000] + "\n... (代码过长，已截断)"
        
        pef_framework = {
            "step1_triple": "P/E/F 三元组分解：P=主体(名称/类型/边界), E_in=可控输入, E_out=不可控输入, F=结果(是否可追溯至(P,E,t))",
            "step2_causal": "因果链验证：F=Φ(P,E_in,E_out,t)是否成立？有无结果先于原因？有无断裂调用链？",
            "step3_seven_dim": "七维评分(0-1)：S1主体完整性, S2架构完整性, S3变量分流, S4规范偏差, S5时序因果, S6边界覆盖, S7可验证性",
            "rho_formula": "ρ = ||S_norm - S_spec|| / ||S_spec||，S_spec为全1基准",
            "dual_gate": "闸门1逻辑合规(因果链PASS+无时序悖论) AND 闸门2工程合规(ρ<λ, standard档λ=0.8)",
            "expected_output": """JSON: {
  "triple": {"P": "...", "E_in": [...], "E_out": [...], "F": "..."},
  "causal_chain": {"verdict": "PASS|FAIL|WARN", "evidence": [...]},
  "seven_dim": {"S1": {"score": 0.0, "evidence": "..."}, ...},
  "rho": 0.0,
  "dual_gate": {"gate1": true, "gate2": true, "final": "PASS|FAIL"}
}""",
        }
        
        return {
            "status": "inline_pending",
            "findings": [],
            "count": 0,
            "reason": "Inline 模式：由对话模型完成 PEF 结构化审查",
            "inline_context": {
                "layer": "L9",
                "name": "PEF 结构化审查",
                "framework": pef_framework,
                "code_file": target,
                "code": code,
                "strictness": "standard (λ=0.8)",
            }
        }
    
    # API 模式：调用 pef_reviewer.py
    if not os.path.isfile(target):
        return {"status": "skipped", "findings": [], "count": 0,
                "reason": "PEF 审查仅支持单文件（目录扫描请逐个文件调用）"}
    
    try:
        result = subprocess.run(
            [sys.executable, script, target, "--strictness", "standard"],
            capture_output=True, text=True, timeout=180
        )
        data = json.loads(result.stdout)
        if data.get("status") == "ok":
            findings = data.get("findings", [])
            pef_detail = data.get("pef_detail", {})
            for f in findings:
                if f.get("category") == "PEF_VERDICT":
                    f["pef_detail"] = pef_detail
            return {"status": "ok", "findings": findings, "count": len(findings)}
        else:
            return {"status": "skipped", "findings": [], "count": 0,
                    "reason": data.get("reason", "PEF 审查跳过")}
    except Exception as e:
        return {"status": "error", "findings": [], "error": str(e)}


# ========== 报告合并与裁决 ==========

SEVERITY_ORDER = {"critical": 0, "p0": 0, "high": 1, "p1": 1, "medium": 2, "p2": 2, "low": 3, "p3": 3, "info": 4, "warning": 2}
# Task8: 置信分级排序优先级（HIGH 置顶优先人工审查；LOW 垫底进独立桶）
CONFIDENCE_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2}

def merge_reports(layer_results: dict) -> dict:
    """合并各层报告，统一裁决"""
    all_findings = []
    layer_summary = {}
    
    for layer_name, result in layer_results.items():
        status = result.get("status", "error")
        if status == "ok":
            all_findings.extend(result["findings"])
            layer_summary[layer_name] = {
                "status": "ok",
                "findings_count": result["count"],
            }
        elif status == "skipped":
            layer_summary[layer_name] = {
                "status": "skipped",
                "reason": result.get("reason", "不适用"),
                "findings_count": 0,
            }
        elif status == "inline_pending":
            layer_summary[layer_name] = {
                "status": "pending_inline",
                "reason": result.get("reason", "由对话模型完成"),
                "findings_count": 0,
            }
        else:
            layer_summary[layer_name] = {
                "status": "error",
                "error": result.get("error", "unknown"),
                "findings_count": 0,
            }
    
    # 按严重级排序（Task8: 增加置信分级高低，HIGH 置顶优先人工审查）
    all_findings.sort(key=lambda x: (
        CONFIDENCE_ORDER.get(x.get("confidence", "LOW"), 2),
        SEVERITY_ORDER.get(x.get("severity", "info"), 9),
    ))

    # Task8: LOW 置信告警进独立桶（只降级/分桶，不静默删除），且不参与裁决计数
    low_confidence_findings = [f for f in all_findings if f.get("confidence") == "LOW"]
    all_findings = [f for f in all_findings if f.get("confidence") != "LOW"]
    
    # 统计
    severity_counts = {}
    category_counts = {}
    file_counts = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = f.get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        fn = f.get("file", "unknown")
        file_counts[fn] = file_counts.get(fn, 0) + 1
    
    # 裁决
    has_critical = any(s in severity_counts for s in ("critical", "p0"))
    has_high = any(s in severity_counts for s in ("high", "p1"))
    if has_critical:
        verdict = "FAIL"
        verdict_reason = "检出 P0/Critical 级问题，必须修复"
    elif has_high:
        verdict = "WARN"
        verdict_reason = "检出 P1/High 级问题，建议修复"
    elif all_findings:
        verdict = "PASS_WITH_NOTES"
        verdict_reason = "仅检出低级别问题，可通过"
    else:
        verdict = "PASS"
        verdict_reason = "未检出问题"
    
    return {
        "schema": "pef-code-audit-v1.0",
        "timestamp": datetime.now().isoformat(),
        "target": "",
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "total_findings": len(all_findings),
        "severity_distribution": severity_counts,
        "category_distribution": category_counts,
        "top_files": dict(sorted(file_counts.items(), key=lambda x: -x[1])[:10]),
        "layer_summary": layer_summary,
        "findings": all_findings,
        "low_confidence_findings": low_confidence_findings,
    }


def format_text_report(report: dict) -> str:
    """格式化为文本报告"""
    lines = []
    lines.append("=" * 70)
    lines.append("  PEF 多层代码审查报告")
    lines.append("=" * 70)
    lines.append(f"  目标: {report['target']}")
    lines.append(f"  时间: {report['timestamp']}")
    lines.append(f"  裁决: {report['verdict']} — {report['verdict_reason']}")
    lines.append(f"  总发现: {report['total_findings']}")
    lines.append("")
    
    lines.append("--- 各层状态 ---")
    for layer, summary in report["layer_summary"].items():
        if summary["status"] == "ok":
            status = "✓"
            count = summary.get("findings_count", 0)
            lines.append(f"  {status} {layer}: {count} 项发现")
        elif summary["status"] == "skipped":
            reason = summary.get("reason", "不适用")
            lines.append(f"  - {layer}: 跳过 ({reason})")
        elif summary["status"] == "pending_inline":
            reason = summary.get("reason", "由对话模型完成")
            lines.append(f"  ◐ {layer}: 待对话模型审查 ({reason})")
        else:
            err = summary.get("error", "unknown")
            lines.append(f"  ✗ {layer}: 错误 ({err})")
    lines.append("")
    
    lines.append("--- 严重级分布 ---")
    for sev, count in sorted(report["severity_distribution"].items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9)):
        lines.append(f"  {sev.upper()}: {count}")
    lines.append("")
    
    if report["findings"]:
        lines.append("--- 问题明细（前 30 条）---")
        for i, f in enumerate(report["findings"][:30]):
            lines.append(f"  [{i+1}] ({f['layer']}) {f['severity'].upper()} | {f['file']}:{f['line']}")
            lines.append(f"      {f['category']}: {f['message'][:100]}")
            if f.get("causal_chain"):
                lines.append(f"      因果链: {f['causal_chain']}")
            if f.get("suggestion"):
                lines.append(f"      修复建议: {f['suggestion'][:100]}")
        if len(report["findings"]) > 30:
            lines.append(f"  ... 还有 {len(report['findings']) - 30} 条，详见 JSON")

    # Task8: LOW 置信告警独立桶（仅展示，不参与裁决）
    if report.get("low_confidence_findings"):
        lowlist = report["low_confidence_findings"]
        lines.append("")
        lines.append(f"--- LOW置信告警独立桶（{len(lowlist)} 条，不参与裁决）---")
        for f in lowlist[:30]:
            lines.append(f"  ({f['layer']}) {f.get('severity', 'info').upper()} | {f.get('file', '')}:{f.get('line', 0)}")
            lines.append(f"      {f.get('category', '')}: {str(f.get('message', ''))[:90]}")
        if len(lowlist) > 30:
            lines.append(f"  ... 还有 {len(lowlist) - 30} 条 LOW，详见 JSON")
    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ========== 主入口 ==========

def main():
    if len(sys.argv) < 2:
        print("用法: python3 audit_pipeline.py <目标路径> [--output report.json] [--format json|text]")
        sys.exit(1)
    
    target = sys.argv[1]
    output_file = None
    fmt = "text"
    
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--output" and i + 1 < len(args):
            output_file = args[i + 1]
            i += 2
        elif args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        else:
            i += 1
    
    if not os.path.exists(target):
        print(f"错误: 目标路径不存在: {target}")
        sys.exit(1)
    
    # 检测工具
    tools = detect_tools()
    print(f"检测到可用工具: {list(tools.keys())}")
    print(f"扫描目标: {target}")
    print()
    
    # 分层执行
    layer_results = {}
    
    # L0 编译器粗筛
    compiler = tools.get("gcc") or tools.get("clang")
    if compiler:
        print(f"[L0] 运行编译器粗筛 ({os.path.basename(compiler)} -Wall -Wextra)...")
        layer_results["L0-Compiler"] = run_compiler_check(target, compiler)
        st = layer_results["L0-Compiler"]
        if st["status"] == "skipped":
            print(f"     -> 跳过: {st.get('reason', '')}")
        else:
            print(f"     -> {st.get('count', 0)} 项")
    
    if "semgrep" in tools:
        print("[L1] 运行 Semgrep...")
        layer_results["L1-Semgrep"] = run_semgrep(target, tools["semgrep"])
        print(f"     -> {layer_results['L1-Semgrep'].get('count', 0)} 项")
    
    if "cppcheck" in tools:
        print("[L2] 运行 cppcheck...")
        layer_results["L2-cppcheck"] = run_cppcheck(target, tools["cppcheck"])
        print(f"     -> {layer_results['L2-cppcheck'].get('count', 0)} 项")
    
    if "bandit" in tools:
        print("[L3] 运行 bandit...")
        layer_results["L3-bandit"] = run_bandit(target, tools["bandit"])
        print(f"     -> {layer_results['L3-bandit'].get('count', 0)} 项")
    
    print("[L1/L3-补充] 运行本地白盒规则...")
    layer_results["L1-LocalRules"] = run_local_rules(target)
    print(f"     -> {layer_results['L1-LocalRules'].get('count', 0)} 项")
    
    if "gitleaks" in tools:
        print("[L4] 运行 gitleaks...")
        layer_results["L4-gitleaks"] = run_gitleaks(target, tools["gitleaks"])
        print(f"     -> {layer_results['L4-gitleaks'].get('count', 0)} 项")
    
    if "trivy" in tools:
        print("[L5] 运行 trivy（依赖漏洞+配置）...")
        layer_results["L5-trivy"] = run_trivy(target, tools["trivy"])
        print(f"     -> {layer_results['L5-trivy'].get('count', 0)} 项")
    
    if "cle_probe" in tools:
        print("[L6] 运行 CLE 物理不变量探针...")
        layer_results["L6-CLE-Probe"] = run_cle_probe(target, tools["cle_probe"])
        print(f"     -> {layer_results['L6-CLE-Probe'].get('count', 0)} 项")
    
    # L7 冒烟测试（多语言自适应：C/C++ 编译运行 + Python 导入检测）
    print("[L7] 运行冒烟测试（多语言自适应）...")
    layer_results["L7-Smoke"] = run_smoke_test(target, compiler)
    st = layer_results["L7-Smoke"]
    if st["status"] == "skipped":
        print(f"     -> 跳过: {st.get('reason', '')}")
    else:
        print(f"     -> {st.get('count', 0)} 项")
    
    # L8 语义审查（优先 ocr 增强，失败退回 Inline）
    layer_results["L8-Semantic"] = {"status": "skipped", "findings": [], "count": 0}
    
    # 先试 ocr（如果已安装）
    if "ocr" in tools:
        print("[L8] 运行 ocr 行级精准审查...")
        ocr_result = run_ocr_review(target, tools["ocr"])
        if ocr_result["status"] == "ok" and ocr_result["count"] > 0:
            layer_results["L8-Semantic"] = ocr_result
            print(f"     -> ocr 检出 {ocr_result['count']} 项")
        else:
            reason = ocr_result.get("reason", ocr_result.get("error", ""))
            print(f"     -> ocr 不可用（{reason}），退回 Inline 模式")
    
    # 退回 Inline 模式
    if layer_results["L8-Semantic"]["status"] != "ok":
        print("[L8] 运行 LLM 语义审查（Inline 模式）...")
        layer_results["L8-Semantic"] = run_semantic_review(target)
        st = layer_results["L8-Semantic"]
        if st["status"] == "skipped":
            print(f"     -> 跳过: {st.get('reason', '')}")
        elif st["status"] == "error":
            print(f"     -> 错误: {st.get('error', '')}")
        elif st["status"] == "inline_pending":
            print(f"     -> Inline 模式: 由对话模型完成审查")
        else:
            print(f"     -> {st.get('count', 0)} 项")
    
    
    # L9 PEF 结构化审查（三元分解+因果链+七维评分+双闸门）
    if "pef_review" in tools:
        print("[L9] 运行 PEF 结构化审查（三元分解+因果链+七维评分）...")
        layer_results["L9-PEF"] = run_pef_review(target, tools["pef_review"])
        st = layer_results["L9-PEF"]
        if st["status"] == "skipped":
            print(f"     -> 跳过: {st.get('reason', '')}")
        elif st["status"] == "error":
            print(f"     -> 错误: {st.get('error', '')}")
        elif st["status"] == "inline_pending":
            print(f"     -> Inline 模式: 由对话模型完成审查")
        else:
            print(f"     -> {st.get('count', 0)} 项")
    
    # 合并报告
    print("\n合并报告...")
    report = merge_reports(layer_results)
    report["target"] = target
    report["available_tools"] = list(tools.keys())
    
    # 收集 inline 待审查上下文
    inline_contexts = {}
    for layer_name, layer_result in layer_results.items():
        if layer_result.get("status") == "inline_pending":
            inline_contexts[layer_name] = layer_result.get("inline_context", {})
    if inline_contexts:
        report["inline_review_pending"] = inline_contexts
    
    # 输出
    if fmt == "json":
        output = json.dumps(report, ensure_ascii=False, indent=2)
    else:
        output = format_text_report(report)
    
    print(output)
    
    # 打印 inline 审查上下文（供对话模型读取）
    if inline_contexts and fmt == "text":
        print("\n" + "=" * 70)
        print("  INLINE 审查上下文（对话模型请基于以下内容完成 L8/L9）")
        print("=" * 70)
        for layer_name, ctx in inline_contexts.items():
            print(f"\n--- {layer_name}: {ctx.get('name', '')} ---")
            if "prompt" in ctx:
                print(f"审查要求: {ctx['prompt'][:300]}...")
            if "framework" in ctx:
                fw = ctx["framework"]
                print(f"步骤1: {fw.get('step1_triple', '')[:100]}")
                print(f"步骤2: {fw.get('step2_causal', '')[:100]}")
                print(f"步骤3: {fw.get('step3_seven_dim', '')[:120]}")
                print(f"偏差率: {fw.get('rho_formula', '')}")
                print(f"双闸门: {fw.get('dual_gate', '')}")
            if "code_files" in ctx:
                for cf in ctx["code_files"]:
                    print(f"\n代码文件: {cf['file']}")
                    print(f"代码长度: {len(cf['code'])} 字符")
            if "code_file" in ctx:
                print(f"\n代码文件: {ctx['code_file']}")
                print(f"代码长度: {len(ctx.get('code', ''))} 字符")
                print(f"严格度: {ctx.get('strictness', '')}")
        print("\n" + "=" * 70)
        print("  对话模型请完成上述 L8/L9 审查，并将结果追加到最终报告中")
        print("=" * 70)
    
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            if fmt == "json":
                json.dump(report, f, ensure_ascii=False, indent=2)
            else:
                f.write(output)
        print(f"\n报告已保存: {output_file}")


if __name__ == "__main__":
    main()
