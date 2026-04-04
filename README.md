# Dead-Code-Forensic — 死代码法医

> 不只找死代码，还要查清谁写的、为什么写的、删了会不会炸

## 怎么用

```bash
# 在 Claude Code 里直接说
帮我找这个项目的死代码

# 或命令行
python3 scripts/forensic.py -o report.md
```

## 输出示例

```
# 死代码检测报告

> 扫描文件数: 47
> 死代码项: 23
> 注释掉的代码块: 8

## 安全分级

  可安全删除:      18  ← 直接删
  需谨慎确认:       3  ← 先检查外部引用
  需人工审查:       2  ← 手动确认

## 谁写的死代码？

| 作者  | 死代码项 |
|-------|---------|
| 张三  | 15      |
| 李四  | 8       |

## 死代码详情

#### `processLegacyData` (函数) 位于 `src/utils/legacy.ts:42`

  function processLegacyData(data: any) {

- 原因: 导出了但没有任何文件引用
- 作者: 张三 (2025-08-15, 234 天前)
- 提交: `a1b2c3d` — feat: add data migration for v1 users
- 判定: 谨慎删除 — 当初为 v1 迁移写的，可能还有用
```

## 检测能力

- 未使用的函数/类/变量/导出/接口/类型
- 注释掉的代码块（2+ 行代码式注释）
- Git blame 考古（谁写的、什么时候、commit 说了什么）
- 三级安全评估（可安全删除 / 需谨慎确认 / 需人工审查）
- 按作者统计死代码责任
- 按文件排名"重灾区"

## 支持语言

Python / JavaScript / TypeScript / Go / Java / Rust

## 零依赖

Python 3.9+ 标准库 + git CLI
