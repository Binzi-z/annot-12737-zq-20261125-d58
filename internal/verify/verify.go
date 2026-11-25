// Package verify is the INDEPENDENT truth-set checker.
//
// It deliberately defines its own report/truth DTOs and its own comparison
// logic: it must not import quaraudit/internal/engine or any classification
// code, so a shared bug in the engine cannot silently agree with the checker.
// It compares an emitted report JSON document item by item against a
// hand-authored truth document, and additionally cross-checks chain witnesses.
package verify

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ---------- independent wire DTOs (only the fields we check) ----------

type wireReport struct {
	Schema               string      `json:"schema"`
	CaseID               string      `json:"case_id"`
	Summary              wireSummary `json:"summary"`
	MinimalNonRecyclable []struct {
		FileID         string   `json:"file_id"`
		WitnessRecords []string `json:"witness_records"`
		ChainIDs       []string `json:"chain_ids"`
	} `json:"minimal_non_recyclable"`
	Files []struct {
		FileID          string   `json:"file_id"`
		Verdict         string   `json:"verdict"`
		ReasonCode      string   `json:"reason_code"`
		WitnessRecords  []string `json:"witness_records"`
		BlockingRecords []string `json:"blocking_records"`
	} `json:"files"`
	RecordResults []struct {
		RecordID       string   `json:"record_id"`
		Status         string   `json:"status"`
		ReasonCode     string   `json:"reason_code"`
		ChainIDs       []string `json:"chain_ids"`
		MatchedFileIDs []string `json:"matched_file_ids"`
	} `json:"record_results"`
	Chains []struct {
		ChainID    string `json:"chain_id"`
		RecordID   string `json:"record_id"`
		FileID     string `json:"file_id"`
		Status     string `json:"status"`
		ReasonCode string `json:"reason_code"`
	} `json:"chains"`
	BoundaryViolations []struct {
		RecordID string `json:"record_id"`
		FileID   string `json:"file_id"`
		Kind     string `json:"kind"`
	} `json:"boundary_violations"`
}

type wireSummary struct {
	LogicalFiles       int `json:"logical_files"`
	Held               int `json:"held"`
	Blocked            int `json:"blocked"`
	Free               int `json:"free"`
	RecordsTotal       int `json:"records_total"`
	RecordsComplete    int `json:"records_complete"`
	RecordsBroken      int `json:"records_broken"`
	RecordsRevoked     int `json:"records_revoked"`
	RecordsSelf        int `json:"records_self_only"`
	BoundaryViolations int `json:"boundary_violations"`
}

// Truth is the hand-authored expectation document.
type Truth struct {
	Schema         string          `json:"schema"`
	CaseID         string          `json:"case_id"`
	ExpectFiles    []ExpectFile    `json:"expect_files"`
	ExpectRecords  []ExpectRecord  `json:"expect_records"`
	ExpectSummary  *ExpectSummary  `json:"expect_summary,omitempty"`
	ExpectBoundary *ExpectBoundary `json:"expect_boundary,omitempty"`
}

// ExpectFile is the expected per-file verdict.
type ExpectFile struct {
	FileID         string   `json:"file_id"`
	Verdict        string   `json:"verdict"`
	ReasonCode     string   `json:"reason_code,omitempty"`
	WitnessRecords []string `json:"witness_records,omitempty"`
}

// ExpectRecord is the expected per-record outcome.
type ExpectRecord struct {
	RecordID   string `json:"record_id"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code,omitempty"`
}

// ExpectSummary gives optional exact summary counts.
type ExpectSummary struct {
	LogicalFiles    *int `json:"logical_files,omitempty"`
	Held            *int `json:"held,omitempty"`
	Blocked         *int `json:"blocked,omitempty"`
	Free            *int `json:"free,omitempty"`
	RecordsTotal    *int `json:"records_total,omitempty"`
	RecordsComplete *int `json:"records_complete,omitempty"`
	RecordsBroken   *int `json:"records_broken,omitempty"`
	RecordsRevoked  *int `json:"records_revoked,omitempty"`
	RecordsSelf     *int `json:"records_self_only,omitempty"`
	Boundary        *int `json:"boundary_violations,omitempty"`
}

// ExpectBoundary checks the number and (optional) kind of boundary violations.
type ExpectBoundary struct {
	Count int    `json:"count"`
	Kind  string `json:"kind,omitempty"`
}

// Entry is one itemized verification line.
type Entry struct {
	Kind   string `json:"kind"` // file | record | summary | invariant | boundary
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Outcome is the full verification result.
type Outcome struct {
	Schema  string  `json:"schema"`
	OK      bool    `json:"ok"`
	Passed  int     `json:"passed"`
	Failed  int     `json:"failed"`
	Entries []Entry `json:"entries"`
}

// Check compares report JSON bytes against truth JSON bytes item by item.
func Check(reportBytes, truthBytes []byte) (*Outcome, error) {
	var rep wireReport
	if err := json.Unmarshal(reportBytes, &rep); err != nil {
		return nil, fmt.Errorf("report json: %w", err)
	}
	var truth Truth
	if err := json.Unmarshal(truthBytes, &truth); err != nil {
		return nil, fmt.Errorf("truth json: %w", err)
	}

	o := &Outcome{Schema: "quaraudit.verify/v1", OK: true, Entries: []Entry{}}
	add := func(kind, name string, ok bool, format string, args ...any) {
		e := Entry{Kind: kind, Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)}
		o.Entries = append(o.Entries, e)
		if ok {
			o.Passed++
		} else {
			o.Failed++
			o.OK = false
		}
	}

	if truth.CaseID != "" {
		add("invariant", "case_id", rep.CaseID == truth.CaseID,
			"report case_id=%q truth=%q", rep.CaseID, truth.CaseID)
	}

	fileByID := map[string]int{}
	for i, f := range rep.Files {
		fileByID[f.FileID] = i
	}
	recByID := map[string]int{}
	for i, r := range rep.RecordResults {
		recByID[r.RecordID] = i
	}
	chainByID := map[string]int{}
	for i, c := range rep.Chains {
		chainByID[c.ChainID] = i
	}

	// ---- per-file item-by-item ----
	for _, ef := range truth.ExpectFiles {
		idx, ok := fileByID[ef.FileID]
		if !ok {
			add("file", ef.FileID, false, "file missing from report")
			continue
		}
		rf := rep.Files[idx]
		if rf.Verdict != ef.Verdict {
			add("file", ef.FileID, false, "verdict expected %s got %s", ef.Verdict, rf.Verdict)
			continue
		}
		if ef.ReasonCode != "" && rf.ReasonCode != ef.ReasonCode {
			add("file", ef.FileID, false, "reason expected %s got %s", ef.ReasonCode, rf.ReasonCode)
			continue
		}
		if ef.Verdict == "BLOCKED" && ef.ReasonCode == "" && rf.ReasonCode == "" {
			add("file", ef.FileID, false, "BLOCKED file must carry an explicit reason_code")
			continue
		}
		// Witness semantics.
		switch ef.Verdict {
		case "HELD":
			if len(rf.WitnessRecords) == 0 {
				add("file", ef.FileID, false, "HELD file has no witness records")
				continue
			}
			if ef.WitnessRecords != nil {
				if !sameSet(rf.WitnessRecords, ef.WitnessRecords) {
					add("file", ef.FileID, false, "witnesses expected %v got %v",
						sorted(ef.WitnessRecords), sorted(rf.WitnessRecords))
					continue
				}
			}
		case "BLOCKED", "FREE":
			if len(rf.WitnessRecords) != 0 {
				add("file", ef.FileID, false, "%s file must not carry complete witnesses, got %v",
					ef.Verdict, rf.WitnessRecords)
				continue
			}
		}
		add("file", ef.FileID, true, "verdict=%s reason=%s witnesses=%v",
			rf.Verdict, dash(rf.ReasonCode), sorted(rf.WitnessRecords))
	}

	// Every report file should be expected (guards against silent extras).
	expectedFiles := map[string]bool{}
	for _, ef := range truth.ExpectFiles {
		expectedFiles[ef.FileID] = true
	}
	for _, rf := range rep.Files {
		if !expectedFiles[rf.FileID] {
			add("file", rf.FileID, false, "unexpected extra file in report (not in truth)")
		}
	}

	// ---- per-record item-by-item ----
	for _, er := range truth.ExpectRecords {
		idx, ok := recByID[er.RecordID]
		if !ok {
			add("record", er.RecordID, false, "record missing from report")
			continue
		}
		rr := rep.RecordResults[idx]
		if rr.Status != er.Status {
			add("record", er.RecordID, false, "status expected %s got %s", er.Status, rr.Status)
			continue
		}
		if er.ReasonCode != "" && rr.ReasonCode != er.ReasonCode {
			add("record", er.RecordID, false, "reason expected %s got %s", er.ReasonCode, rr.ReasonCode)
			continue
		}
		if er.Status == "BROKEN" && rr.ReasonCode == "" {
			add("record", er.RecordID, false, "BROKEN record must carry a reason_code")
			continue
		}
		add("record", er.RecordID, true, "status=%s reason=%s", rr.Status, dash(rr.ReasonCode))
	}
	expectedRecs := map[string]bool{}
	for _, er := range truth.ExpectRecords {
		expectedRecs[er.RecordID] = true
	}
	for _, rr := range rep.RecordResults {
		if !expectedRecs[rr.RecordID] {
			add("record", rr.RecordID, false, "unexpected extra record result (not in truth)")
		}
	}

	// ---- summary exact counts ----
	if es := truth.ExpectSummary; es != nil {
		checkInt := func(name string, want *int, got int) {
			if want == nil {
				return
			}
			add("summary", name, *want == got, "expected %d got %d", *want, got)
		}
		checkInt("logical_files", es.LogicalFiles, rep.Summary.LogicalFiles)
		checkInt("held", es.Held, rep.Summary.Held)
		checkInt("blocked", es.Blocked, rep.Summary.Blocked)
		checkInt("free", es.Free, rep.Summary.Free)
		checkInt("records_total", es.RecordsTotal, rep.Summary.RecordsTotal)
		checkInt("records_complete", es.RecordsComplete, rep.Summary.RecordsComplete)
		checkInt("records_broken", es.RecordsBroken, rep.Summary.RecordsBroken)
		checkInt("records_revoked", es.RecordsRevoked, rep.Summary.RecordsRevoked)
		checkInt("records_self_only", es.RecordsSelf, rep.Summary.RecordsSelf)
		checkInt("boundary_violations", es.Boundary, rep.Summary.BoundaryViolations)
	}

	// ---- boundary expectations ----
	if eb := truth.ExpectBoundary; eb != nil {
		ok := len(rep.BoundaryViolations) == eb.Count
		if ok && eb.Kind != "" {
			for _, v := range rep.BoundaryViolations {
				if v.Kind != eb.Kind {
					ok = false
				}
			}
		}
		add("boundary", "violations", ok, "expected count=%d kind=%q got %d %v",
			eb.Count, eb.Kind, len(rep.BoundaryViolations), violationKinds(rep))
	}

	// ---- independent structural invariants over chains/witnesses ----

	// Every HELD file listed in minimal set must agree with the Files section
	// and every witness must be a COMPLETE record whose chain is COMPLETE and
	// terminates at that file.
	minSetIDs := map[string]bool{}
	for _, h := range rep.MinimalNonRecyclable {
		minSetIDs[h.FileID] = true
		fi, ok := fileByID[h.FileID]
		if !ok {
			add("invariant", "minset:"+h.FileID, false, "in minimal set but absent from files")
			continue
		}
		if rep.Files[fi].Verdict != "HELD" {
			add("invariant", "minset:"+h.FileID, false, "in minimal set but verdict=%s", rep.Files[fi].Verdict)
			continue
		}
		bad := ""
		for _, cid := range h.ChainIDs {
			ci, ok := chainByID[cid]
			if !ok {
				bad = "missing chain " + cid
				break
			}
			ch := rep.Chains[ci]
			if ch.Status != "COMPLETE" || ch.FileID != h.FileID {
				bad = fmt.Sprintf("chain %s status=%s file=%s", cid, ch.Status, ch.FileID)
				break
			}
		}
		if bad != "" {
			add("invariant", "chains:"+h.FileID, false, bad)
		} else {
			add("invariant", "chains:"+h.FileID, true, "%d complete chain(s) verify", len(h.ChainIDs))
		}
	}
	for _, f := range rep.Files {
		if f.Verdict == "HELD" && !minSetIDs[f.FileID] {
			add("invariant", "minset:"+f.FileID, false, "HELD file missing from minimal_non_recyclable")
		}
	}

	// Summary held count must equal minimal-set length.
	add("invariant", "summary_held_eq_set",
		rep.Summary.Held == len(rep.MinimalNonRecyclable),
		"summary.held=%d minimal_set=%d", rep.Summary.Held, len(rep.MinimalNonRecyclable))

	return o, nil
}

// FormatLines returns human-readable itemized verification lines.
func (o *Outcome) FormatLines() []string {
	lines := make([]string, 0, len(o.Entries)+2)
	for _, e := range o.Entries {
		mark := "PASS"
		if !e.OK {
			mark = "FAIL"
		}
		lines = append(lines, fmt.Sprintf("[%s] %-9s %-14s %s", mark, e.Kind, e.Name, e.Detail))
	}
	verdict := "ALL CHECKS PASSED"
	if !o.OK {
		verdict = fmt.Sprintf("%d CHECK(S) FAILED", o.Failed)
	}
	lines = append(lines, fmt.Sprintf("---- verified %d items: %d passed, %d failed — %s",
		len(o.Entries), o.Passed, o.Failed, verdict))
	return lines
}

func sameSet(a, b []string) bool {
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func sorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func violationKinds(r wireReport) []string {
	out := []string{}
	for _, v := range r.BoundaryViolations {
		out = append(out, v.Kind+":"+v.RecordID)
	}
	return out
}
