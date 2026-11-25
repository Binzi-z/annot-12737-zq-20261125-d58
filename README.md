# 沙箱目录中的隔离引用复核

获确认的题面位于 task/PROMPT.txt。使用原生 Windows 和标准库，输入与验证使用本地合成数据。

## 作答实现（Go，零第三方依赖，全程离线、不操作真实目录）

完整设计、口径与题目要求对照见 **[`SOLUTION.md`](SOLUTION.md)**。

```powershell
# 一键：gofmt + vet + 全部测试（真值逐条独立验证 + 5 万文件边界）+ 审计 + 独立验证器
powershell -ExecutionPolicy Bypass -File .\run.ps1

# 或只跑测试
go test ./... -count=1
```

- `internal/winpath`：盘符大小写 / 重复分隔符 / `/` 与 `\` / 空白填充 / 内部空格 / `.` `..` 的纯逻辑规范化，段边界前缀。
- `internal/alias`：水位版本化重解析别名、最长段前缀、嵌套、环检测、租户/scope 边界。
- `internal/engine`：事件流重放、重命名、`undo_sync` 撤销、引用链、最小不可回收集合（同逻辑目标去重）。
- `internal/verify`：**不导入引擎**的独立验证器，对手写真值集 `testdata/truth/expected_small.json` 逐条对照。
- `internal/synth`：确定性 **50,000 文件**世界与“换一条别名”的目录/租户边界测试（含独立预言机）。

实测：`go test ./...` 全部通过；独立验证器 **52 项逐条 PASS**；
50,000 文件中换别名仅影响恰好 2,000 个别名子树文件，**0** 条越过 `green2`/`green-backup`
陷阱目录或 40,000 个其他租户文件，跨租户改指被 `TENANT_BOUNDARY_CROSSED` 阻断。

真实生成的产物：

- `examples/report_small.json` / `report_small.txt`：审计报告（最小集合 + 18 条链）。
- `examples/verification_small.txt`：独立验证器逐条结果。
- `examples/scale_boundary_report.json`：5 万文件边界结论。
