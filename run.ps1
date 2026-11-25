# run.ps1 — 原生 Windows 离线审计演练入口（仅需 Go + 标准库，无第三方依赖）
#
# 用法（在仓库根目录）:
#   powershell -ExecutionPolicy Bypass -File .\run.ps1
#
# 它会：格式化检查 -> go vet -> 跑全部测试（含独立验证器逐条对照与
# 50,000 文件换别名边界测试，并重新生成 examples 下的真实产物）
# -> 命令行审计小样 -> 进程外独立验证器逐条对照。

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

Step "Go 版本"
go version

Step "gofmt 检查/格式化"
$unformatted = @(gofmt -l .)
if ($unformatted.Count -gt 0) {
    Write-Host "以下文件需要格式化，已执行 gofmt -w："
    $unformatted | ForEach-Object { Write-Host "  $_"; gofmt -w $_ }
} else {
    Write-Host "全部文件符合 gofmt 规范。"
}

Step "go vet ./..."
go vet ./...

Step "go test ./... -count=1  （真值逐条验证 + 5 万文件边界）"
go test ./... -count=1

Step "生成小样审计报告 (JSON + 文本)"
go run ./cmd/audit `
    -case testdata/truth/case_small.json `
    -json examples/report_small.json `
    -text examples/report_small.txt

Step "独立验证器逐条对照（进程外，不导入引擎）"
go run ./cmd/verify `
    -report examples/report_small.json `
    -truth testdata/truth/expected_small.json

Write-Host "`n全部完成。产物见 examples/ 与测试日志。" -ForegroundColor Green
