# Code Review Officer

> **诚实定位**：L0–L5 是 battle-tested 开源工具的**组装**，我们的核心贡献不是这些工具本身，而是：
> 1. **判决聚合层**（pef-code-audit-v1.0 schema）：统一四态裁决 + P0/P1/low 分级 + causal_chain 因果链字段
> 2. **L6 CLE 物理不变量探针**：AI 空壳代码 / 幻觉 / 因果链断裂检测
> 3. **L8 LLM 语义审查**：理解代码意图，判断逻辑正确性
> 4. **L9 PEF 结构化审查**：P/E/F 三元分解 + 因果链 + 七维评分 + 双闸门
>
> **不冒充自研反而加分**：gcc / Semgrep / cppcheck / bandit / gitleaks / trivy 全部是成熟开源工具，本项目不冒充。任何人用 GitHub Actions 半天能搭出类似 L0–L5 组合。真正的差异化在 L6 / L8 / L9 和判决聚合层。

---

十层递进式综合代码审查工作流：

```
L0 编译器粗筛 → L1 Semgrep → L2 cppcheck → L3 bandit → L4 gitleaks → L5 trivy → L6 CLE 物理不变量探针 → L7 冒烟测试 → L8 LLM 语义审查 → L9 PEF 结构化审查
```

自动检测可用工具，统一输出报告，并给出最终裁决（FAIL / WARN / PASS_WITH_NOTES / PASS）。

---

## 与 mega-linter / super-linter 的区别

| 维度 | mega-linter / super-linter | code-review-officer |
|------|---------------------------|---------------------|
| L0-L5 静态分析 | ✅ 核心功能 | ✅ 同样用这些工具 |
| AI 幻觉检测 | ❌ | ✅ L6 专门层 |
| 逻辑正确性判断 | ❌ | ✅ L8 LLM 语义审查 |
| 结构化判决框架 | ❌（各自为政） | ✅ L9 PEF 三元分解 + 七维评分 |
| 统一裁决 schema | ❌ | ✅ pef-code-audit-v1.0 |
| 运行时实证 | ❌ | ✅ L7 冒烟测试 |

---

## 各层独有检出矩阵

> 哪类 bug 只有哪层能抓到。这比"十层"这个数字有说服力。

| Bug 类型 | 只有哪层能抓到 | 其他层为什么抓不到 |
|----------|---------------|-------------------|
| 编译错误 / 类型不匹配 | L0 编译器 | 其他层不做类型检查 |
| 密钥泄露（API key / 密码） | L4 gitleaks | 语义审查不会主动搜密钥模式 |
| 依赖包已知 CVE | L5 trivy | 语义审查不懂 CVE 数据库 |
| 空壳函数 / 假逻辑 / TODO 占位 | L6 CLE 探针 | 静态分析规则匹配不到"意图" |
| 段错误 / 运行时崩溃 | L7 冒烟测试 | 静态分析不执行代码 |
| 逻辑错误 / 时序悖论 / 因果链断裂 | L8 LLM 语义 | 规则匹配不到语义层 bug |
| P/E/F 三元分解 / 七维评分 | L9 PEF 结构化 | L8 是自由判断，L9 是确定性框架 |

---

## 信噪比校准说明

> **737+ 发现只有 3 个 P0** — 信噪比才是真问题，不是再加一层工具的事，是 severity 校准。

- **过宽 except Exception**：对物流批处理项目是**刻意设计**（单条数据坏了不能崩整批），标记为 P2 不阻断
- **真实 silent except**（完全吞错无日志）：约 51 处，标记为 P1 建议逐步优化
- **真正的 P0（崩溃级）**：空指针解引用、除零、污点命令注入 — 这个项目 0 处

判决聚合层的价值：把 700+ 条原始告警，校准成 **3 个需要立刻修的 P0 + 51 个建议修的 P1 + 其余记录待办**。

---

## Inline 模式（默认，零 API Key）

1. 脚本自动跑完 L0-L7 确定性工具层。
2. L8/L9 输出审查上下文，由当前对话中的 AI 直接完成：
   - L8：语义级逻辑审查、意图理解、AI 幻觉识别。
   - L9：P/E/F 三元分解、因果链验证、七维锚向量评分、双闸门裁决。
3. 合并为完整十层报告。

无需配置任何外部 LLM API Key。

## API 模式（可选）

设置 `LLM_API_KEY` 后，脚本可自动调用 OpenAI 兼容接口完成 L8/L9。

## 快速开始

```bash
python resources/audit_pipeline.py <target-file-or-directory>
```

脚本会自动检测本机可用工具；未安装的层会标记为 skipped，不影响其他层运行。

## 案例

- [十层工作流 vs 单层 CLE 探针：有效性证据与增量分析（2026-09-18）](docs/cases/case_ten_layer_vs_single_cle_20260918.md)

## 目录结构

- `SKILL.md`：完整使用说明与工作流定义。
- `resources/audit_pipeline.py`：十层审查主脚本。
- `rules/`：审查规则与配置。
- `examples/`：示例代码。
- `docs/cases/`：真实审查案例与有效性分析。
