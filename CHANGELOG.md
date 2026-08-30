# 更新日志

## v0.2.4 (2026-08-30)

表述修正：统一对外表述。

## v0.2.3 (2026-08-30)

表述修正：统一为「MIT 开源发布、能力开放」的对外表述。

## v0.2.2 (2026-08-30)

安全家族检测能力增强 + 措辞规范（与元信 / 元安 / 元审 v0.2.2 对齐）：

- **报告 / 留痕联动**：`report generate` 新增 `scans` 联动字段（引用元信装前扫描 / 元安深度扫描 /
  元审四阶段审查的报告与 verdict），Markdown 报告输出「安全扫描联动」视图、JSON 输出 `scans` 数组；
  每次成功生成报告自动写一条 `report.generate` 操作留痕（audit.log），形成「目标 → 扫描 → 测试 → 结论」
  的完整留痕链。
- **措辞规范**：正文不再写版本号；统一对外表述（含代码注释与报告输出）。
- 测试：447 / 447 全绿（Python 3.8 / 3.13）。

## v0.1.0 (2026-08-29)


初始发布：

- 定位：元测 —— 有纪律的 AI 安全测试方法论（市场主线「纵深」线 M6）。
  对**已授权目标**（自有资产 / SRC 众测·bug bounty / CTF·靶场 / 本地靶机）按
  侦察 → 发现 → 验证 → 报告 四阶段做 Web 安全测试；**不是靶场技能、更不是攻击工具**。
- Scope Guard 五道防线（硬产品机制，非口头免责）：
  ① 范围守卫：CLI `scope check <target>` 双保险，未授权目标默认拒绝（exit 1），云元数据等绝对禁止（exit 2）；
  ② 默认指向合法环境：本地靶场 / CTF / 已授权真实目标 / SRC；
  ③ 授权声明机制：`scope init` / `scope add`，授权以 ~/.yottasec/scope.json 为准，不信任口头声明；
  ④ 法律红线声明：中国《网络安全法》《刑法》第 285 / 286 条；定位 = 方法论 / 教材；
  ⑤ 操作留痕：audit log（JSONL 默认开启，无 --no-audit，可过滤 / 导出）。
- CLI：零依赖（Python 3.8+ 标准库）yotta_security_testing.py —— scope init / check / list / add / remove +
  report generate（Markdown / JSON，敏感凭据脱敏）+ audit log；目标三层判定 + 内置黑名单
  （.gov / .mil 需 --type explicit）。
- playbooks：00 方法论 + 01-12 十二个漏洞 playbook（SQLi / XSS / SSRF / XXE / 反序列化 /
  鉴权与访问控制 / API / 命令注入 / 文件上传 / 业务逻辑 / 信息泄露 / 不安全配置），
  每篇固定六节 + 「类」表述脱敏 + 靶场 / 授权目标 / SRC 双场景。
- references：tutorial.md（中文教程，新手全流程，含 SRC 实战）+ report-template.md
  （findings schema 对齐 CLI report generate，含 SRC 平台提交字段映射）。
- 测试：444 用例（含 311 项文档结构 / 脱敏 / SRC 覆盖自测）Python 3.8 + 3.13 双版本全绿。
- 文档：SKILL.md + README 中英双版 + 四方式安装（发布规范 §3.3.1）。