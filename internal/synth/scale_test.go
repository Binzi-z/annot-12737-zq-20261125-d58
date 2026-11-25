package synth_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quaraudit/internal/alias"
	"quaraudit/internal/engine"
	"quaraudit/internal/synth"
	"quaraudit/internal/tenant"
	"quaraudit/internal/winpath"
)

// independentBelowAlias is the test's OWN segment-prefix oracle. It deliberately
// does not call alias.Table or winpath.HasSegmentPrefix, so a longest-prefix or
// rewrite bug cannot validate itself. It implements just enough normalization
// for the deterministic noise used by synth.
func independentBelowAlias(raw, aliasCanonical string) bool {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "/", `\`)

	var b strings.Builder
	prevBackslash := false
	for _, r := range strings.ToLower(s) {
		if r == '\\' {
			if prevBackslash {
				continue // collapse duplicated separators
			}
			prevBackslash = true
		} else {
			prevBackslash = false
		}
		b.WriteRune(r)
	}
	norm := b.String()

	segs := strings.Split(strings.Trim(norm, `\`), `\`)
	want := strings.Split(strings.Trim(strings.ToLower(aliasCanonical), `\`), `\`)
	if len(segs) < len(want) {
		return false
	}
	for i := range want {
		if segs[i] != want[i] {
			return false
		}
	}
	return true
}

func tenantMap(w *synth.ScaleWorld) *tenant.Map {
	roots := []tenant.Root{}
	for _, tr := range w.Case.TenantRoots {
		p, err := winpath.Normalize(tr.Root)
		if err != nil {
			panic(err)
		}
		roots = append(roots, tenant.Root{Tenant: tr.Tenant, Root: p.Key})
	}
	return tenant.NewMap(roots...)
}

// TestFiftyThousand_AliasChangeDoesNotCrossBoundaries is the headline scale
// boundary test: among exactly 50,000 files, re-pointing one alias must change
// resolution for EXACTLY the alias subtree — never a sibling directory with a
// look-alike name, never another tenant.
func TestFiftyThousand_AliasChangeDoesNotCrossBoundaries(t *testing.T) {
	w := synth.BuildScale(50000)
	if got := len(w.Case.Files); got != 50000 {
		t.Fatalf("generated %d files, want exactly 50000", got)
	}
	tm := tenantMap(w)

	v1 := alias.NewTable([]alias.Spec{w.AliasSpec(w.OldTarget)})
	v2 := alias.NewTable([]alias.Spec{w.AliasSpec(w.NewTarget)})
	v3cross := alias.NewTable([]alias.Spec{w.AliasSpec(w.CrossTarget)})

	start := time.Now()
	oracleHits, changed := 0, 0

	for i, raw := range w.RawAccess {
		k, err := winpath.Normalize(raw)
		if err != nil {
			t.Fatalf("i=%d raw %q normalize: %v", i, raw, err)
		}
		oracle := independentBelowAlias(raw, string(w.AliasKey))
		if oracle {
			oracleHits++
		}

		// Baseline (old target) must resolve every access to its own file.
		r1 := v1.Resolve(k.Key, w.Watermark, tm)
		if !r1.OK {
			t.Fatalf("i=%d baseline resolve failed: %s %s", i, r1.Code, r1.Message)
		}
		if r1.Final != w.FileKeys[i] {
			t.Fatalf("i=%d baseline mismatch\n raw=%q\n got =%q\n want=%q", i, raw, r1.Final, w.FileKeys[i])
		}

		// Re-point within the same tenant.
		r2 := v2.Resolve(k.Key, w.Watermark, tm)
		if !r2.OK {
			t.Fatalf("i=%d re-point resolve failed: %s", i, r2.Code)
		}
		isChanged := r2.Final != r1.Final
		if isChanged != oracle {
			t.Fatalf("i=%d containment violation: resolver changed=%v independent-oracle=%v\n raw=%q\n v1=%q\n v2=%q",
				i, isChanged, oracle, raw, r1.Final, r2.Final)
		}

		if oracle {
			changed++
			if ten := tm.TenantOf(r2.Final); ten != w.BoundaryTenant {
				t.Fatalf("i=%d alias re-point crossed tenant: final=%q tenant=%q", i, r2.Final, ten)
			}
			if !winpath.HasSegmentPrefix(r2.Final, w.NewTarget) {
				t.Fatalf("i=%d changed target %q not under new alias target %q", i, r2.Final, w.NewTarget)
			}
			suffix, ok := winpath.StripPrefix(r2.Final, w.NewTarget)
			if !ok || len(suffix) != 1 || !strings.HasPrefix(suffix[0], "g_") {
				t.Fatalf("i=%d suffix not preserved after re-point: %v ok=%v", i, suffix, ok)
			}
		} else if r2.Final != w.FileKeys[i] {
			t.Fatalf("i=%d unrelated path changed after alias flip:\n got %q\n want %q", i, r2.Final, w.FileKeys[i])
		}

		// A cross-tenant re-point must be DENIED for alias-routed paths and
		// must leave every unrelated path untouched.
		r3 := v3cross.Resolve(k.Key, w.Watermark, tm)
		if oracle {
			if r3.OK || r3.Code != alias.CodeTenantCross {
				t.Fatalf("i=%d cross-tenant alias not blocked: ok=%v code=%q", i, r3.OK, r3.Code)
			}
		} else if !r3.OK || r3.Final != w.FileKeys[i] {
			t.Fatalf("i=%d cross-target alias leaked onto unrelated path: ok=%v code=%q final=%q",
				i, r3.OK, r3.Code, r3.Final)
		}
	}

	if oracleHits != 2000 {
		t.Fatalf("independent oracle hits=%d, want 2000 alias-subtree files", oracleHits)
	}
	if changed != len(w.AliasAccessIndices) || changed != 2000 {
		t.Fatalf("changed=%d alias-index-count=%d, want 2000", changed, len(w.AliasAccessIndices))
	}

	// Explicit look-alike directory traps must never move.
	for _, i := range w.TrapIndices {
		k, _ := winpath.Normalize(w.RawAccess[i])
		r := v2.Resolve(k.Key, w.Watermark, tm)
		if !r.OK || r.Final != w.FileKeys[i] {
			t.Fatalf("trap i=%d leaked: ok=%v final=%q want=%q", i, r.OK, r.Final, w.FileKeys[i])
		}
		if independentBelowAlias(w.RawAccess[i], string(w.AliasKey)) {
			t.Fatalf("trap i=%d incorrectly classified below alias by oracle", i)
		}
	}

	// Every other tenant must be untouched and stay in its own tenant root.
	for _, i := range w.OtherTenantIndices {
		k, _ := winpath.Normalize(w.RawAccess[i])
		r := v2.Resolve(k.Key, w.Watermark, tm)
		if !r.OK || r.Final != w.FileKeys[i] {
			t.Fatalf("other-tenant i=%d changed", i)
		}
		if got := tm.TenantOf(r.Final); got != w.FileTenant[i] {
			t.Fatalf("i=%d tenant changed to %q want %q", i, got, w.FileTenant[i])
		}
	}

	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("50k boundary sweep too slow: %v", d)
	} else {
		t.Logf("50k boundary sweep OK in %v (2000 alias-routed, %d traps, %d other-tenant)",
			d, len(w.TrapIndices), len(w.OtherTenantIndices))
		writeScaleArtifact(t, map[string]any{
			"test":                  "TestFiftyThousand_AliasChangeDoesNotCrossBoundaries",
			"files":                 50000,
			"alias_routed_files":    oracleHits,
			"resolution_changed":    changed,
			"prefix_trap_files":     len(w.TrapIndices),
			"other_tenant_files":    len(w.OtherTenantIndices),
			"cross_tenant_repoint":  "blocked:" + alias.CodeTenantCross,
			"unrelated_paths_moved": 0,
			"elapsed_ms":            d.Milliseconds(),
			"pass":                  true,
		})
	}
}

// writeScaleArtifact best-effort materializes a scale result JSON under
// ../../examples (the module-root examples dir when run via go test ./...).
func writeScaleArtifact(t *testing.T, doc map[string]any) {
	t.Helper()
	for _, dir := range []string{filepath.Join("..", "..", "examples"), "examples"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "scale_boundary_report.json"), append(b, '\n'), 0o644); err == nil {
			return
		}
	}
}

// TestFiftyThousand_FullAuditSampledReferences runs the whole engine over 50k
// retained files with 2500 noisy exact references and expects every one to
// verify with zero broken chains.
func TestFiftyThousand_FullAuditSampledReferences(t *testing.T) {
	w := synth.BuildScale(50000)
	n, selected := w.AddSampledReferences(20)
	if n != 2500 {
		t.Fatalf("sampled refs=%d want 2500", n)
	}

	start := time.Now()
	rep, err := engine.Audit(w.Case)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("full 50k audit too slow: %v", d)
	} else {
		t.Logf("full 50k audit in %v", d)
	}

	if rep.Summary.LogicalFiles != 50000 {
		t.Fatalf("logical files=%d want 50000 (canonical collision?)", rep.Summary.LogicalFiles)
	}
	if rep.Summary.RecordsTotal != n || rep.Summary.RecordsComplete != n {
		t.Fatalf("records total=%d complete=%d want all %d complete (broken=%d revoked=%d self=%d)",
			rep.Summary.RecordsTotal, rep.Summary.RecordsComplete, n,
			rep.Summary.RecordsBroken, rep.Summary.RecordsRevoked, rep.Summary.RecordsSelf)
	}
	if rep.Summary.RecordsBroken != 0 || rep.Summary.Blocked != 0 {
		t.Fatalf("expected zero broken/blocked at scale, got broken=%d blocked=%d",
			rep.Summary.RecordsBroken, rep.Summary.Blocked)
	}
	if rep.Summary.Held != n {
		t.Fatalf("held=%d want %d", rep.Summary.Held, n)
	}

	byID := map[string]string{}
	for _, f := range rep.Files {
		byID[f.FileID] = f.Verdict
	}
	for _, i := range selected {
		id := w.Case.Files[i].ID
		if byID[id] != "HELD" {
			t.Fatalf("selected %s (i=%d) verdict=%s want HELD", id, i, byID[id])
		}
	}
}
