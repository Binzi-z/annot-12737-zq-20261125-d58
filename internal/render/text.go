// Package render renders reports as human-readable offline audit text.
package render

import (
	"fmt"
	"strings"

	"quaraudit/internal/report"
)

// Text renders a Chinese-language plain-text audit report.
func Text(r *report.Report) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("================================================================")
	w(" 隔离目录保留物 · 跨沙箱引用离线审计报告")
	w(" 案例: %s   模式: %s", r.CaseID, r.Schema)
	if r.Title != "" {
		w(" 说明: %s", r.Title)
	}
	w(" 隔离根(逻辑路径): %s", r.QuarantineRoot)
	w(" 归属沙箱: %s", r.OwnerSandbox)
	w("================================================================")
	s := r.Summary
	w("")
	w("[总览] 清单输入 %d 行 -> 去重后逻辑文件 %d 个 (合并重复行 %d)",
		s.RetainedInputRows, s.LogicalFiles, s.MergedDuplicateRows)
	w("       不可回收 HELD=%d  证据断环 BLOCKED=%d  可回收 FREE=%d", s.Held, s.Blocked, s.Free)
	w("       引用记录 %d: 完整=%d 断环=%d 已撤销=%d 仅本沙箱=%d",
		s.RecordsTotal, s.RecordsComplete, s.RecordsBroken, s.RecordsRevoked, s.RecordsSelf)
	w("       引用链 %d 条 (完整 %d); 边界违规 %d", s.ChainsTotal, s.ChainsComplete, s.BoundaryViolations)

	w("")
	w("----------------------------------------------------------------")
	w("[1] 最小不能回收文件集合 (%d 个唯一逻辑目标)", len(r.MinimalNonRecyclable))
	w("    注: 同一逻辑目标的多条别名/记录只计一次。")
	w("----------------------------------------------------------------")
	if len(r.MinimalNonRecyclable) == 0 {
		w("  (无)")
	}
	for i, h := range r.MinimalNonRecyclable {
		w("  %2d. %s  [%s]", i+1, h.FileID, h.LogicalKey)
		if len(h.AllFileIDs) > 1 {
			w("      合并清单行: %s", strings.Join(h.AllFileIDs, ", "))
		}
		if h.Tenant != "" {
			w("      租户: %s", h.Tenant)
		}
		w("      见证记录: %s", strings.Join(h.WitnessRecords, ", "))
		w("      引用链:   %s", strings.Join(h.ChainIDs, ", "))
	}

	w("")
	w("----------------------------------------------------------------")
	w("[2] 断环/证据待定 (%d) — 每条都给出明确阻断原因", len(r.BlockedPendingEvidence))
	w("----------------------------------------------------------------")
	if len(r.BlockedPendingEvidence) == 0 {
		w("  (无)")
	}
	for _, bf := range r.BlockedPendingEvidence {
		w("  ! %s  %s", bf.FileID, bf.LogicalKey)
		w("      阻断原因: %s", bf.ReasonCode)
		if bf.ReasonMessage != "" {
			w("      详情: %s", bf.ReasonMessage)
		}
		w("      相关声称记录: %s", strings.Join(bf.ClaimRecords, ", "))
	}

	w("")
	w("----------------------------------------------------------------")
	w("[3] 可回收文件 (%d)", len(r.Recyclable))
	w("----------------------------------------------------------------")
	for _, f := range r.Recyclable {
		w("  o %-6s %s", f.FileID, f.LogicalKey)
	}

	if len(r.BoundaryViolations) > 0 {
		w("")
		w("----------------------------------------------------------------")
		w("[4] 目录/租户边界违规 (%d) — 别名更换不得造成此类跨越", len(r.BoundaryViolations))
		w("----------------------------------------------------------------")
		for _, v := range r.BoundaryViolations {
			w("  x 记录 %s -> 文件 %s  [%s]", v.RecordID, dash(v.FileID), v.Kind)
			w("      %s", v.Detail)
		}
	}

	if len(r.Warnings) > 0 {
		w("")
		w("[警告]")
		for _, wn := range r.Warnings {
			w("  ? %s", wn)
		}
	}

	w("")
	w("----------------------------------------------------------------")
	w("[5] 可验证引用链明细 (%d 条)", len(r.Chains))
	w("----------------------------------------------------------------")
	for _, c := range r.Chains {
		file := c.FileID
		if file == "" {
			file = "-"
		}
		w("")
		w("  %s  记录=%s 文件=%s 状态=%s", c.ChainID, c.RecordID, file, c.Status)
		if c.ReasonCode != "" {
			w("      原因码: %s — %s", c.ReasonCode, c.ReasonMessage)
		}
		for _, lk := range c.Links {
			switch {
			case lk.From != "" && lk.To != "":
				w("      · [%s] %s", lk.Kind, lk.Detail)
				w("          %s", oneLine(lk.From))
				w("       -> %s", oneLine(lk.To))
			case lk.Detail != "":
				w("      · [%s] %s", lk.Kind, lk.Detail)
			}
		}
	}

	w("")
	w("================================================================")
	w(" 结论: %d 个逻辑文件确有他沙箱有效引用，不可回收；%d 个存在断环", s.Held, s.Blocked)
	w("       需按阻断原因核查；其余 %d 个在逻辑证据层面可回收。", s.Free)
	w("================================================================")
	return b.String()
}

// oneLine keeps a raw path on a single report line: outer padding is trimmed and
// embedded CR/LF/tab control runes are collapsed to spaces. The untouched raw
// value is still preserved verbatim in the JSON report.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	return strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
