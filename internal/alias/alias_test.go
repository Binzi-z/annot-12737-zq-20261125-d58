package alias

import (
	"testing"

	"quaraudit/internal/tenant"
	"quaraudit/internal/winpath"
)

func k(t *testing.T, s string) winpath.Key {
	t.Helper()
	p, err := winpath.Normalize(s)
	if err != nil {
		t.Fatalf("normalise %q: %v", s, err)
	}
	return p.Key
}

func TestWatermarkVersioning(t *testing.T) {
	aliasKey := k(t, `R:\rot`)
	oldT := k(t, `C:\oldstore`)
	newT := k(t, `C:\newstore`)
	tab := NewTable([]Spec{
		{ID: "AL", Op: OpUpsert, WM: 1, Alias: aliasKey, Target: oldT},
		{ID: "AL", Op: OpUpsert, WM: 7, Alias: aliasKey, Target: newT},
	})
	ref := k(t, `R:\rot\f.bin`)

	if got := tab.Resolve(ref, 3, nil); !got.OK || got.Final != k(t, `C:\oldstore\f.bin`) {
		t.Fatalf("wm3 = %+v, want oldstore", got)
	}
	if got := tab.Resolve(ref, 8, nil); !got.OK || got.Final != k(t, `C:\newstore\f.bin`) {
		t.Fatalf("wm8 = %+v, want newstore", got)
	}
}

func TestFutureAliasIsInactiveAtEarlyWatermarkAndDiagnostic(t *testing.T) {
	aliasKey := k(t, `W:\future`)
	target := k(t, `C:\wf`)
	tab := NewTable([]Spec{{ID: "F", Op: OpUpsert, WM: 9, Alias: aliasKey, Target: target}})
	ref := k(t, `W:\future\f.bin`)

	got := tab.Resolve(ref, 3, nil)
	if got.OK || got.Code != CodeInactiveAtWM {
		t.Fatalf("want inactive break, got %+v", got)
	}
	if got.Diagnostic != k(t, `C:\wf\f.bin`) {
		t.Fatalf("diagnostic = %q", got.Diagnostic)
	}
}

func TestLongestPrefixSegmentBoundary(t *testing.T) {
	link := k(t, `M:\link`)
	target := k(t, `C:\dst`)
	tab := NewTable([]Spec{{ID: "L", Op: OpUpsert, WM: 1, Alias: link, Target: target}})

	inside := k(t, `m:\link\sub\f`)
	if got := tab.Resolve(inside, 2, nil); !got.OK || got.Final != k(t, `c:\dst\sub\f`) {
		t.Fatalf("inside resolve = %+v", got)
	}
	// "link2" must not be rewritten by the "link" alias.
	trap := k(t, `M:\link2\f`)
	if got := tab.Resolve(trap, 2, nil); !got.OK || got.Final != trap {
		t.Fatalf("trap leaked: %+v", got)
	}
}

func TestCycleDetected(t *testing.T) {
	a := k(t, `Q:\a`)
	b := k(t, `Q:\b`)
	tab := NewTable([]Spec{
		{ID: "CA", Op: OpUpsert, WM: 1, Alias: a, Target: b},
		{ID: "CB", Op: OpUpsert, WM: 1, Alias: b, Target: a},
	})
	got := tab.Resolve(k(t, `Q:\a\x`), 2, nil)
	if got.OK || got.Code != CodeCycle {
		t.Fatalf("want cycle, got %+v", got)
	}
}

func TestBoundaryTenantCrossBlocked(t *testing.T) {
	aliasKey := k(t, `V:\globex\portal`)
	target := k(t, `V:\acme\secret`)
	tm := tenant.NewMap(
		tenant.Root{Tenant: "globex", Root: k(t, `V:\globex`)},
		tenant.Root{Tenant: "acme", Root: k(t, `V:\acme`)},
	)
	tab := NewTable([]Spec{{ID: "X", Op: OpUpsert, WM: 1, Alias: aliasKey, Target: target, BoundaryTenant: "globex"}})
	got := tab.Resolve(k(t, `V:\globex\portal\f`), 2, tm)
	if got.OK || got.Code != CodeTenantCross {
		t.Fatalf("want tenant cross block, got %+v", got)
	}
}
