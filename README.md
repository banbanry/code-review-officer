# Code Review Officer

十层递进式综合代码审查工作流：

`L0 编译器粗筛 → L1 Semgrep → L2 cppcheck → L3 bandit → L4 gitleaks → L5 trivy → L6 CLE 物理不变量探针 → L7 冒烟测试 → L8 LLM 语义审查 → L9 PEF 结构化审查`

自动检测可用工具，统一输出报告，并给出最终裁决。

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

## 目录结构

- `SKILL.md`：完整使用说明与工作流定义。
- `resources/audit_pipeline.py`：十层审查主脚本。
- `rules/`：审查规则与配置。
- `examples/`：示例代码。
