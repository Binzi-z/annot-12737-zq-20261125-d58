# 隔离目录保留物 · 跨沙箱引用离线审计（Go / 原生 Windows / 纯标准库）

工单目标：删除隔离目录前，确认其中的保留物是否仍被**另一个沙箱**引用。
本演练**只处理逻辑路径与合成引用记录**：不读取、不扫描、不改动任何真实系统目录，
所有“文件”都只是 JSON 清单里的逻辑条目。

- 语言：Go（`go 1.22` 指令，实测 `go1.27.4 windows/amd64`），**零第三方依赖**。
- 路径处理全部为字符串逻辑运算，**不调用** `filepath.Abs`、`os.Stat`、`EvalSymlinks` 等任何会落到真实文件系统的能力。
- 一条 `go test ./...` 即可完成：单元测试、小型真值集“独立验证器逐条对照”、以及 **50,000 文件换一条别名**的目录/租户边界测试。

---

## 1. 一键运行（原生 Windows）

```powershell
# 在仓库根目录
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

或手动执行等价命令：

```powershell
go test ./... -count=1                                   # 全部测试（含下面两项硬指标）
go run ./cmd/audit  -case testdata/truth/case_small.json `
     -json examples/report_small.json -text examples/report_small.txt
go run ./cmd/verify -report examples/report_small.json `
     -truth testdata/truth/expected_small.json           # 独立验证器逐条对照
```

> `go test` 运行根包测试时会用**真实引擎输出**重新生成
> `examples/report_small.json`、`examples/report_small.txt`、
> `examples/verification_small.txt`，规模测试会生成
> `examples/scale_boundary_report.json`，因此这些产物始终与代码一致。

目录结构：

```
cmd/audit      审计 CLI（JSON 案例 -> JSON/文本报告）
cmd/verify     独立验证器 CLI（报告 JSON + 手写真值 -> 逐条 PASS/FAIL，非零退出）
internal/winpath  纯逻辑 Windows 路径规范化 + 段边界前缀
internal/alias    水位版本化虚拟重解析别名表 / 最长段前缀 / 嵌套 / 环 / 边界
internal/tenant   最长前缀租户根映射
internal/model    合成案例输入 DTO
internal/report   稳定报告 schema 与原因码
internal/engine   离线审计引擎（事件重放、重命名、undo、建链、最小集合）
internal/render   中文纯文本报告
internal/verify   ★独立验证器（自带 DTO 与判定，不导入 engine）
internal/synth    确定性 5 万文件世界生成器 + 规模边界测试
testdata/truth/   小型真值案例 + 手写期望
examples/         真实生成的报告 / 逐条验证记录 / 规模结论
```

---

## 2. 路径规范化：覆盖题面的所有“写法差异”

`internal/winpath` 对每条原始字符串做且仅做逻辑规范化，得到唯一身份键 `Key`
（整体小写，因为 Windows 名大小写不敏感）：

1. 去掉首尾 Unicode 空白填充（空格 / Tab / `\r` / `\n`）；
2. `/` 与 `\` 等价，连续分隔符折叠（`C:\\\\A//B` == `C:\A\B`）；
3. 盘符规范化：显示用大写 `C:`，身份键用小写 `c:`；
4. 逻辑解析 `.` / `..`（根之上的 `..` 丢弃，不会越卷）；
5. **内部空格是有效字符，原样保留**（`Program Files`、`sub dir/f 04.bin`）；
6. 支持 `\\server\share\...` UNC；
7. 离线无法确定的**盘相对路径** `C:foo`、相对路径 `a\b` 直接判错而不是猜。

前缀判断是**段边界感知**的：`...\mnt\green` 不会前缀命中
`...\mnt\green2` 或 `...\mnt\green-backup`（这正是朴素字符串前缀替换会漏的越界点）。

---

## 3. 水位可变别名表与“同一目标不是多份副本”

`internal/alias` 把每个别名 ID 建模为一串带水位（watermark）的版本
（`alias_upsert` / `alias_remove`，按 `(wm, seq)` 排序）。

- 引用记录在某个水位 `W` 观察到，就用 `wm <= W` 的最新版本解析，因此“别名表在不同水位可变”可被精确还原：
  同一 `R:\rot\f14` 在 `wm=3` 解析到 `oldstore`（有效并命中 F14），在 `wm=8`
  解析到改名后的 `newstore`（落空，形成断环 REF-14B）。
- 采用**最长已知别名前缀 + 逐段重写 + 迭代嵌套**：`B:\base\files-link\...`
  会先走 `AL-BASE` 再走 `AL-LINK`，链中每一跳都落为可验证的 `alias_reparse` 链接。
- 环检测（重复别名 ID / 超 32 跳）→ `ALIAS_CYCLE`。
- 若某别名键“存在但在该水位不活跃”（尚未建立 / 已删除），不会被当成普通目录，
  而是明确断环 `ALIAS_INACTIVE_AT_WATERMARK`，并尽量用最新表给出 `diagnostic_final`
  以便把断环声明确认到某个保留物。
- 别名可钉死 `boundary_tenant`：重写目标一旦落入别的租户根，立即
  `TENANT_BOUNDARY_CROSSED` 阻断；可选 `scope` 根越界 → `ALIAS_SCOPE_ESCAPED`。

**去重原则**：文件身份是规范化后的逻辑 `Key`。无论多少条引用记录、多少个别名、
多少种大小写/分隔符写法指向同一个 `Key`，在 `files` 与最小集合中都只是**一个逻辑文件**；
多条记录保留为不同的“见证（witness）”，而不是被计成多份不可回收副本。
清单自身若有多行规范化到同一 `Key`，也会合并并在 `all_file_ids` 中保留全部原始 ID。

---

## 4. 重命名到达与“撤销同步”

输入是按到达顺序组织的合成事件流（`model.Case.Events`）：

- `rename { old_path, new_path, batch? }`：有效重命名形成前向映射，
  允许“记录用旧名、清单用新名”仍可验证成链（真值 F05 / REF-05）。
- `undo_sync { undo_batch }`：**最终态**下，该同步批次送达的两类内容都被撤销：
  - 批次内的引用记录 → `REVOKED / RECORD_BATCH_UNDONE`，该声称彻底失效，文件可回收（F06）；
  - 批次内的重命名 → 不进入有效前向映射，单独进“已撤销重命名”表。
    此时若仍有一条**不在该撤销批次内**的旧名引用，引擎不会静默匹配，而是断环
    `BROKEN / RENAME_BATCH_UNDONE`，并把新名保留物置为 `BLOCKED` 等待人工确认（F07 / REF-07）。

“先到达重命名、后到达撤销”的顺序无关最终判定：只要存在对应 `undo_sync`，
批次即被标记撤销；撤销先到、批次后到也同样生效。

---

## 5. 报告口径：最小不可回收集合 + 断环阻断原因

每个逻辑文件给出三态结论（优先级 `HELD > BLOCKED > FREE`）：

| 结论 | 含义 | 是否计入“最小不能回收集合” |
|---|---|---|
| `HELD` | 至少有一条来自**另一个沙箱**、端到端完整且未被撤销、未越租户边界的引用链 | ✅ 是 |
| `BLOCKED` | 存在活跃的“被引用”声称，但链在证据/边界处断裂；不能据此确认仍被引用，也不建议在核查前删除 | ❌ 单独列入“断环/证据待定” |
| `FREE` | 没有存活的外部声称（含已撤销、仅本沙箱、目录前缀之外） | ❌ 可回收 |

- **最小不能回收文件集合** `minimal_non_recyclable[]`：只含 `HELD` 的唯一逻辑目标，
  每项给出 `witness_records` 与可复核的 `chain_ids`。
- **引用链** `chains[]`：每条链由有序链接组成
  （`record → normalize → alias_reparse* → rename_forward* → inventory_match/prefix_match → terminal`），
  每跳带 `from/to`、别名 ID、生效水位，机器可验算。
- **断环原因码**（每条 `BROKEN` 都必须有 `reason_code` + 人话 `reason_message`）：

| 原因码 | 触发点 |
|---|---|
| `RECORD_BATCH_UNDONE` | 引用随同步批次被 `undo_sync` 撤销（记录态 `REVOKED`） |
| `RENAME_BATCH_UNDONE` | 唯一转发依据是被撤销批次里的重命名 |
| `PATH_MALFORMED` | 原始路径离线无法规范化（空 / 相对 / 盘相对 / UNC 残缺） |
| `ALIAS_INACTIVE_AT_WATERMARK` | 别名在引用水位尚无有效映射（未来才建 / 已删） |
| `ALIAS_CYCLE` | 别名重解析成环或超跳数 |
| `ALIAS_SCOPE_ESCAPED` | 别名目标越过声明的 scope 根（段边界） |
| `TENANT_BOUNDARY_CROSSED` | 别名或记录把 A 租户的引用落到 B 租户保留物 |
| `TARGET_NOT_RETAINED` | 解析成功但清单中没有该保留物（陈旧/指向隔离区外） |
| `SELF_SANDBOX_REFERENCE` | 引用来自隔离目录归属沙箱自身，不算“另一个沙箱”（记录态 `SELF_ONLY`） |

`kind:"tree"` 的记录按**严格段前缀子树**匹配，可一次见证目录下所有保留文件，
但不会覆盖名称相似的兄弟目录（真值 REF-12 覆盖 `tree/a`、`tree/b` 两个文件，
明确**不**覆盖 `tree-other/fc.bin`）。

---

## 6. 小型真值集与独立验证器（逐条对照）

`testdata/truth/case_small.json` 是手写的较小真值世界（14 个保留物、17 条记录），
刻意把题面每个坑都做成可核对条目；`expected_small.json` 是手写期望。

实测审计结论（`examples/report_small.txt`）：

- **HELD = 8**：F01（大小写/重复分隔符/填充直连）、F02（别名）、
  F03（三条不同别名/嵌套/直连记录指向同一目标，只算 1 个文件、3 条见证）、
  F04（内部空格 + Tab/换行填充）、F05（有效重命名）、
  F12A/F12B（tree 子树引用）、F14（旧水位别名目标）。
- **BLOCKED = 3**：F07 `RENAME_BATCH_UNDONE`、F08 `ALIAS_INACTIVE_AT_WATERMARK`、
  F10 `TENANT_BOUNDARY_CROSSED`。
- **FREE = 3**：F06（引用批次已撤销）、F11（仅归属沙箱自身）、F12C（在 tree 前缀之外）。
- 记录态：完整 9 / 断环 6 / 已撤销 1 / 仅本沙箱 1；引用链 18 条（完整 10）；边界违规 1。

`internal/verify` 是**独立验证器**：

- 它**不导入 `internal/engine`**，而是自定义一份只含待校字段的报告 DTO，
  防止引擎与校验器共用同一判定 bug 而“互相同意”；
- 按 `expected_small.json` **逐条**比对每个文件的
  `verdict / reason_code / witness_records` 集合、每条记录的 `status / reason_code`、
  汇总计数与边界违规；报告里多出任何未声明的文件/记录也会判 FAIL；
- 额外做结构性交叉验证：每个 HELD 文件必须出现在最小集合中，其每条 `chain_id`
  必须真实存在、状态为 `COMPLETE` 且终点就是该文件；`summary.held` 必须等于最小集合长度；
- 输出逐条 `[PASS]/[FAIL] ...`（见 `examples/verification_small.txt`），
  `cmd/verify` 在有任何不符时以退出码 1 结束；
- 另有 `TestVerifierRejectsWrongTruth` 故意喂错误期望，证明验证器“有牙齿”，不会空过。

---

## 7. 50,000 文件：换一条别名是否越过目录与租户边界

`internal/synth/scale.go` 确定性生成**恰好 50,000** 个唯一逻辑文件，分布在 5 个租户
（`V:\tenants\t00..t04`，每租户 10,000）。租户 `t00` 内布置：

- `data\green\g_*.dat` 2,000 个：由唯一待测别名
  `V:\tenants\t00\mnt\green -> ...\data\green`（钉死 `boundary_tenant=t00`）暴露；
- `data\blue\b_*.dat` 2,000 个：别名“换目标”后的同租户新目标；
- `mnt\green2\*` 500 个、`mnt\green-backup\*` 500 个：专门的**前缀陷阱兄弟目录**，
  名字能骗过朴素字符串前缀替换；
- 其余为普通目录；其他 4 个租户各 10,000 个文件。

每个访问路径还按索引确定性掺入 `/` 替换、分隔符翻倍、盘符小写、首尾空白等噪声，
确保规模测试真的在压规范化。

`TestFiftyThousand_AliasChangeDoesNotCrossBoundaries`
（`internal/synth/scale_test.go`）对全部 50,000 条访问做三种别名表解析，并用
**测试自带的独立段前缀预言机**（不调用 `alias.Resolver` / `HasSegmentPrefix`）逐行对照：

1. **旧目标**：每条访问都必须解析回它自己的物理文件（基线正确）；
2. **把这一条别名改指同租户 `data\blue`**：解析结果发生变化的集合，必须**恰好等于**
   预言机判定的别名子树集合——实测 **2,000**，一个不多一个不少；
   变化者仍在 `t00` 且后缀文件名逐段保留；其余 **48,000 条全部不变**，
   包括 1,000 个 `green2/green-backup` 陷阱与全部跨租户文件；
3. **把这一条别名改指租户 `t01` 的目录**：所有 2,000 条别名路由访问都必须被
   `TENANT_BOUNDARY_CROSSED` **拒绝**（不允许静默解析），而所有无关路径依旧不变。

同文件的 `TestFiftyThousand_FullAuditSampledReferences` 再对 50,000 保留物 +
2,500 条带噪声、租户匹配的精确引用跑完整引擎，断言逻辑文件仍为 50,000
（无规范化碰撞）、2,500 条全部 `COMPLETE`、HELD=2,500、断环/BLOCKED=0。
结论落到 `examples/scale_boundary_report.json`。规模扫描在普通开发机上为秒级，
测试内设了宽松的 30s 上限用于捕获劣化到 O(N²) 的实现。

---

## 8. 安全边界与可扩展点

- 全程离线、纯逻辑：不会对 `C:\`、`V:\`、真实沙箱目录做任何操作；示例中的盘符路径只是字符串。
- 输入即数据：新增案例只需编写符合 `model.Case` 的 JSON，无需改代码。
- 若将来要接真实清单导出，建议加一个只读 adapter 把导出物转成 `Case`，审计内核与验证器可原样复用；
  真实重解析点信息应作为**别名事件的一个来源**，仍不建议在删除流程中即时跟随。
