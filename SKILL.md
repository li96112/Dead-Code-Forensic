---
name: dead-code-forensic
description: Find dead code with git archaeology — not just unused functions, but WHO wrote them, WHY, WHEN, and whether it's safe to delete. Supports Python, JavaScript, TypeScript, Go, Java, Rust. Detects commented-out code blocks, traces author responsibility, and generates cleanup plans.
metadata: {"openclaw":{"emoji":"🔬","requires":{"bins":["python3","git"]},"homepage":"https://github.com/li96112/Dead-Code-Forensic"}}
---

# Dead-Code-Forensic — 死代码法医

> 不只找死代码，还要查清谁写的、为什么写的、删了会不会炸

带考古报告的死代码清理工具。通过 git blame 追溯每段死代码的作者和 commit 动机，评估删除安全性（SAFE / CAUTION / INVESTIGATE），生成可执行的清理计划。

## Agent 调用方式

当用户提到"死代码"、"清理代码"、"Dead-Code-Forensic"时：

### 扫描当前项目

```bash
python3 {baseDir}/scripts/forensic.py -o /tmp/dead_code_report.md
# 读取 /tmp/dead_code_report.md 展示给用户
```

### 带参数扫描

```bash
# 只扫描特定语言
python3 {baseDir}/scripts/forensic.py --ext .py .js .ts -o /tmp/report.md

# 扫描指定目录
python3 {baseDir}/scripts/forensic.py -d /path/to/project -o /tmp/report.md

# 排除额外目录
python3 {baseDir}/scripts/forensic.py --exclude migrations fixtures -o /tmp/report.md

# 同时输出 JSON 原始数据
python3 {baseDir}/scripts/forensic.py --json /tmp/dead_code.json -o /tmp/report.md
```

### 触发关键词
- "找死代码" / "清理死代码" / "dead code"
- "Dead-Code-Forensic" / "代码清理"
- "哪些代码没用到" / "unused code"
- "代码体检" / "代码卫生"

## 检测能力

| 检测项 | 说明 |
|--------|------|
| **未使用函数** | 定义了但没人调用的函数/方法 |
| **未使用类** | 定义了但没人实例化的类 |
| **未使用变量** | 赋值了但没人读的变量 |
| **未使用导出** | export 了但没人 import |
| **注释掉的代码** | 2+ 行连续的、看起来像代码的注释（不是正常注释） |
| **接口/类型** | TypeScript 的 interface/type 定义但未使用 |

## 法医调查

每个死代码项都包含完整的"犯罪现场"信息：

- **WHO** — git blame 查出的作者
- **WHEN** — 写入时间 + 距今天数
- **WHY** — 对应的 commit message（解释当初为什么写）
- **WHERE** — 精确到文件名:行号
- **VERDICT** — SAFE（直接删）/ CAUTION（检查外部引用）/ INVESTIGATE（手动审查）

## 支持语言

| 语言 | 文件扩展名 | 检测类型 |
|------|-----------|---------|
| Python | .py | 函数 / 类 / 变量 |
| JavaScript | .js .jsx | 函数 / 类 / 变量 / export |
| TypeScript | .ts .tsx | 函数 / 类 / 变量 / export / interface / type |
| Go | .go | 函数 / 结构体 / 变量 |
| Java | .java | 方法 / 类 / 变量 |
| Rust | .rs | 函数 / struct / enum / trait |

## 零依赖

纯 Python 标准库 + git CLI。

## 文件说明

| 文件 | 作用 |
|------|------|
| `scripts/forensic.py` | 核心引擎：多语言扫描 + git blame 考古 + 安全评估 + 报告生成 |
