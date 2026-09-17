---
name: code-review-officer
description: "代码审查官（Code Review Officer）。十层递进式综合代码审查工作流：L0编译器粗筛 → L1 Semgrep → L2 cppcheck → L3 bandit → L4 gitleaks → L5 trivy → L6 CLE物理不变量探针(AI幻觉) → L7冒烟测试 → L8 LLM语义审查 → L9 PEF结构化审查(三元分解+因果链+七维评分)。自动检测可用工具，统一报告，自动裁决。触发词：代码审查、代码审查官、安全扫描、代码审计、bug扫描、冒烟测试、语义审查、PEF审查。"
---

# 代码审查官（Code Review Officer）

> 十层递进式综合代码审查工作流。编译器粗筛 → 多工具静态分析 → AI幻觉检测 → 冒烟测试实证 → LLM语义审查 → PEF结构化审查，一份报告裁决。

## 设计理念

市场上的代码检查工具各有盲区：
- **Semgrep** 广度够但查不出 AI 空壳代码
- **cppcheck/bandit** 语言专项但不跨语言
- **gitleaks** 只管密钥不管逻辑
- **传统 SAST** 假设代码是人写的、诚实的
- **所有静态工具** 都不能判断"代码逻辑是否正确"

本工作流的核心创新：**传统 SAST 的广度 + CLE 物理不变量探针的深度 + LLM 语义审查的理解度**，三层互补覆盖 AI 生成代码的幻觉和"屎山"问题。

## 十层审查架构

```
源代码
  │
  ├─ L0 编译器粗筛   → gcc/clang -Wall -Wextra 编译警告（最基础过滤）
  ├─ L1 Semgrep      → 多语言通用静态分析（3000+ 规则，40+ 语言）
  ├─ L2 cppcheck     → C/C++ 专项深度扫描（内存、缓冲区、未定义行为）
  ├─ L3 bandit       → Python 专项安全扫描（注入、硬编码、危险函数）
  ├─ L4 gitleaks     → 密钥泄露扫描（git 历史 + 当前文件）
  ├─ L5 trivy        → 依赖漏洞 + Dockerfile/IaC 配置扫描
  ├─ L6 CLE 探针     → AI 幻觉 + 物理不变量检测（空壳代码、因果链断裂）
  ├─ L7 冒烟测试     → 编译后运行，检测段错误/崩溃/死循环（运行时验证）
  ├─ L8 LLM 语义审查 → 理解代码意图，判断逻辑正确性（语义级深度）
  └─ L9 PEF 结构化   → P/E/F三元分解+因果链+七维评分+双闸门（确定性框架）
  │
  ▼
统一报告 → 自动裁决（FAIL / WARN / PASS_WITH_NOTES / PASS）
```

| 层 | 工具 | GitHub 开源 | 强项 | 盲区 |
|---|---|---|---|---|
| L0 | gcc/clang | ✅ GNU/LLVM | 语法、类型、未初始化变量 | 只查编译期，不查运行时 |
| L1 | Semgrep | semgrep/semgrep | 多语言、规则丰富、快 | AI 空壳代码查不出 |
| L2 | cppcheck | danmar/cppcheck | C/C++ 内存问题深 | 只支持 C/C++ |
| L3 | bandit | PyCQA/bandit | Python 注入、硬编码 | 只支持 Python |
| L4 | gitleaks | gitleaks/gitleaks | 密钥泄露、git 历史 | 不管逻辑 bug |
| L5 | trivy | aquasecurity/trivy | 依赖 CVE、容器配置 | 不管源码逻辑 |
| L6 | CLE 探针 | 你的 | AI 幻觉、物理不变量 | 已知 CVE 覆盖少 |
| L7 | 冒烟测试 | 内置 | 运行时崩溃、死循环 | 只测空输入，不测业务逻辑 |
| L8 | LLM 语义审查 | 对话模型Inline / API | 逻辑正确性、意图理解、假逻辑 | Inline模式零配置；API模式需key |
| L9 | PEF 结构化审查 | 对话模型Inline / pef-structured-review | 三元分解、因果链、七维评分、双闸门 | Inline模式零配置；API模式需key |

## 快速开始

```bash
# 完整十层扫描（Inline模式，L8/L9由对话AI完成）
python3 resources/audit_pipeline.py <目标文件或目录>

# 输出 JSON 报告
python3 resources/audit_pipeline.py ./src --output report.json --format json

# 文本报告（默认）
python3 resources/audit_pipeline.py ./src --format text
```

**Inline 工作流**：脚本自动跑完 L0-L7（确定性工具），L8/L9 输出审查上下文，由当前对话的 AI 直接完成语义审查和 PEF 结构化审查，最终合并为完整十层报告。无需配置任何 API key。

## 工具安装

```bash
# L1 Semgrep（必装，核心层）
pip install semgrep
# 或: brew install semgrep / pipx install semgrep

# L2 cppcheck（C/C++ 项目必装）
# Ubuntu/Debian: sudo apt install cppcheck
# macOS: brew install cppcheck
# Windows: https://github.com/danmar/cppcheck/releases

# L3 bandit（Python 项目必装）
pip install bandit

# L4 gitleaks（安全基线，推荐）
# macOS: brew install gitleaks
# Linux: 从 GitHub releases 下载二进制
# Windows: scoop install gitleaks

# L5 trivy（供应链安全，可选）
# macOS: brew install trivy
# Linux: 从 GitHub releases 下载

# L6 CLE 探针（随本 Skill 自带）
# 位于 cle-code-probe skill 的 resources/ 目录

# L8/L9 LLM 语义审查 & PEF 结构化审查（可选，需配置 API）
export LLM_API_KEY="your-api-key"
export LLM_BASE_URL="https://api.deepseek.com/v1"  # 默认 DeepSeek
export LLM_MODEL="deepseek-chat"                   # 默认模型
# L9 需要 pef-structured-review skill 已安装（自动检测）
```

> L8/L9 支持两种模式：
> - **Inline 模式（默认）**：不配置 API key，脚本跑完 L0-L7 后输出审查上下文，由当前对话的 AI 直接完成 L8/L9 审查，零额外配置
> - **API 模式**：设置 `LLM_API_KEY` 后脚本自动调用外部 LLM 完成 L8/L9，支持任何 OpenAI 兼容接口

编排器会**自动检测**哪些工具可用，跳过未安装的层，不报错。

## 输出格式

### 裁决等级

| 裁决 | 条件 | 含义 |
|------|------|------|
| **FAIL** | 检出 P0/Critical | 必须修复，不能合并 |
| **WARN** | 检出 P1/High | 建议修复，需人工确认 |
| **PASS_WITH_NOTES** | 仅低级别问题 | 可通过，记录待办 |
| **PASS** | 无问题 | 清洁 |

### 报告结构

```json
{
  "schema": "pef-code-audit-v1.0",
  "verdict": "FAIL",
  "verdict_reason": "检出 P0/Critical 级问题",
  "total_findings": 15,
  "severity_distribution": {"p0": 3, "p1": 5, "low": 7},
  "layer_summary": {
    "L1-Semgrep": {"status": "ok", "findings_count": 5},
    "L6-CLE-Probe": {"status": "ok", "findings_count": 3}
  },
  "findings": [
    {
      "layer": "L6-CLE-Probe",
      "tool": "cle-code-probe",
      "file": "src/auth.c",
      "line": 42,
      "severity": "p0",
      "category": "RESOURCE_BOUND",
      "message": "malloc()返回值未检查NULL",
      "causal_chain": "P[malloc] -> E[no null check] -> F[deref null]"
    }
  ]
}
```

## 与单一工具的区别

| 维度 | 只用 Semgrep | 只用 cppcheck | 本工作流 |
|------|-------------|--------------|---------|
| 语言覆盖 | 40+ | 仅 C/C++ | 40+ + 专项深度 |
| AI 幻觉检测 | ❌ | ❌ | ✅ L6 专门层 |
| 密钥泄露 | ❌ | ❌ | ✅ L4 |
| 依赖漏洞 | ❌ | ❌ | ✅ L5 |
| 统一裁决 | 各自为政 | 各自为政 | ✅ 一份报告 |
| 自验证 | 无 | 无 | ✅ CLE 注入验收 |

## 使用规则

1. **自动检测**：编排器自动检测可用工具，未安装的层跳过并在报告中标注
2. **C/C++ 项目**：优先确保 cppcheck 安装，L2 对内存问题的深度是 Semgrep 不能替代的
3. **Python 项目**：优先确保 bandit 安装
4. **任何项目**：gitleaks 必跑——密钥泄露是最危险的问题
5. **AI 生成代码**：L6 CLE 探针是核心价值层，不要跳过
6. **大项目**：Semgrep 可能较慢，可先用 `--timeout` 限制，或分目录扫描
7. **误报处理**：各层工具的误报率不同，CLE 探针的 P0 发现具有最高可信度（有因果链支撑）

## 与 CLE 探针的关系

本工作流是 CLE 探针的**超集**：
- 只需要 AI 幻觉检测 → 直接用 `cle-code-probe` skill
- 需要全面代码审查（传统 bug + AI 幻觉 + 安全 + 依赖）→ 用本工作流

CLE 探针的结果在报告中标记为 `L6-CLE-Probe`，与其他层的发现并排展示，便于对比哪些是传统工具能发现的、哪些是只有 CLE 能发现的。

## 典型工作流

```
开发提交代码
    │
    ▼
本工作流扫描（六层）
    │
    ├─ FAIL → 阻断合并，输出修复建议
    ├─ WARN → 人工 review，记录待办
    └─ PASS → 允许合并
```

---

*PEF Code Audit Workflow · 六层递进，一份裁决。传统 SAST 的广度 + CLE 探针的深度。*
