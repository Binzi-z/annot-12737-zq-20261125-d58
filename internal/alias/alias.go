// Package alias implements a watermark-versioned virtual-reparse alias table
// and a segment-boundary-safe iterative resolver.
//
// An alias maps one canonical path prefix (the reparse point) to another
// canonical prefix (its target). Aliases are versioned by watermark: the same
// alias id can be re-pointed over time, and references observed at watermark W
// are resolved with the latest operation at or before W.
//
// Resolution never performs filesystem I/O and never treats two records that
// collapse to one logical target as two copies; callers dedupe on Result.Final.
package alias

import (
	"math"
	"sort"

	"quaraudit/internal/tenant"
	"quaraudit/internal/winpath"
)

// Operation kinds for an alias version.
const (
	OpUpsert = "upsert"
	OpRemove = "remove"
)

// Break reason codes produced by the resolver. The audit engine surfaces these
// verbatim (they are the explicit blocking reasons at a broken chain link).
const (
	CodeInactiveAtWM = "ALIAS_INACTIVE_AT_WATERMARK"
	CodeCycle        = "ALIAS_CYCLE"
	CodeTenantCross  = "TENANT_BOUNDARY_CROSSED"
	CodeScopeEscape  = "ALIAS_SCOPE_ESCAPED"
)

// Spec is one versioned alias operation.
type Spec struct {
	ID             string      `json:"id"`
	Op             string      `json:"op"`
	WM             int         `json:"wm"`
	Seq            int         `json:"seq"`
	Alias          winpath.Key `json:"alias"`
	Target         winpath.Key `json:"target"`
	BoundaryTenant string      `json:"boundary_tenant,omitempty"`
	Scope          winpath.Key `json:"scope,omitempty"`
}

// Hop is one performed alias rewrite, a verifiable chain link.
type Hop struct {
	AliasID        string      `json:"alias_id"`
	WM             int         `json:"active_wm"`
	From           winpath.Key `json:"from"`
	To             winpath.Key `json:"to"`
	BoundaryTenant string      `json:"boundary_tenant,omitempty"`
}

// Result is the outcome of resolving a canonical key at a watermark.
type Result struct {
	OK         bool        `json:"ok"`
	Code       string      `json:"code,omitempty"`
	Message    string      `json:"message,omitempty"`
	Final      winpath.Key `json:"final,omitempty"`
	Hops       []Hop       `json:"hops"`
	Diagnostic winpath.Key `json:"diagnostic_final,omitempty"`
}

// Table holds all alias versions indexed by alias prefix key.
type Table struct {
	versions map[winpath.Key][]Spec
}

// NewTable groups specs by alias key and orders versions (wm, then seq).
func NewTable(specs []Spec) *Table {
	t := &Table{versions: make(map[winpath.Key][]Spec)}
	for _, s := range specs {
		if s.Op == "" {
			s.Op = OpUpsert
		}
		t.versions[s.Alias] = append(t.versions[s.Alias], s)
	}
	for k := range t.versions {
		vs := t.versions[k]
		sort.SliceStable(vs, func(i, j int) bool {
			if vs[i].WM != vs[j].WM {
				return vs[i].WM < vs[j].WM
			}
			return vs[i].Seq < vs[j].Seq
		})
		t.versions[k] = vs
	}
	return t
}

// KnownPrefix returns the longest *known* alias key that is a segment prefix
// of cur, whether or not it is active at any particular watermark. This lets
// the resolver report "alias exists but was not active at this watermark".
func (t *Table) KnownPrefix(cur winpath.Key) (winpath.Key, []Spec, bool) {
	var best winpath.Key
	var bestSpecs []Spec
	for _, pk := range winpath.PrefixKeys(cur) {
		if vs, ok := t.versions[pk]; ok {
			best = pk
			bestSpecs = vs
		}
	}
	if best == "" {
		return "", nil, false
	}
	return best, bestSpecs, true
}

// activeAt returns the effective spec at watermark wm. A remove as the latest
// operation means no mapping is active.
func activeAt(vs []Spec, wm int) (Spec, bool) {
	var cur Spec
	found := false
	for _, s := range vs {
		if s.WM <= wm {
			cur = s
			found = true
		} else {
			break
		}
	}
	if !found || cur.Op == OpRemove {
		return cur, false
	}
	return cur, true
}

const maxHops = 32

// Resolve resolves cur at watermark wm. tm may be nil; when non-nil it powers
// per-alias BoundaryTenant checks. On a break, Result.Diagnostic carries a
// best-effort resolution under the newest table so the auditor can tie the
// broken claim to a retained file for investigation.
func (t *Table) Resolve(cur winpath.Key, wm int, tm *tenant.Map) Result {
	res := Result{Hops: []Hop{}}
	seenIDs := map[string]bool{}

	for hop := 0; hop < maxHops; hop++ {
		prefix, vs, known := t.KnownPrefix(cur)
		if !known {
			res.OK = true
			res.Final = cur
			return res
		}

		spec, active := activeAt(vs, wm)
		if !active {
			res.Code = CodeInactiveAtWM
			if latest, ok := latestOp(vs); ok && latest.Op == OpUpsert && latest.WM > wm {
				res.Message = "alias " + latest.ID + " is first mapped at a later watermark than the reference"
			} else {
				res.Message = "alias " + aliasID(vs) + " has no active target at the reference watermark (removed or not yet upserted)"
			}
			res.Diagnostic = t.resolveLatest(cur)
			return res
		}

		if seenIDs[spec.ID] {
			res.Code = CodeCycle
			res.Message = "alias cycle detected revisiting " + spec.ID
			res.Diagnostic = cur
			return res
		}
		seenIDs[spec.ID] = true

		rest, _ := winpath.StripPrefix(cur, prefix)
		next := winpath.ApplyPrefix(spec.Target, rest)

		// Scope containment: an alias may never point outside its declared root.
		if spec.Scope != "" && !winpath.HasSegmentPrefix(spec.Target, spec.Scope) {
			res.Code = CodeScopeEscape
			res.Message = "alias " + spec.ID + " target escapes its declared scope root"
			res.Diagnostic = next
			res.Hops = append(res.Hops, Hop{AliasID: spec.ID, WM: spec.WM, From: cur, To: next, BoundaryTenant: spec.BoundaryTenant})
			return res
		}

		// Tenant boundary pinned on the alias itself.
		if spec.BoundaryTenant != "" && tm != nil {
			if got := tm.TenantOf(spec.Target); got != "" && got != spec.BoundaryTenant {
				res.Code = CodeTenantCross
				res.Message = "alias " + spec.ID + " rewrites into tenant " + got + ", outside boundary tenant " + spec.BoundaryTenant
				res.Diagnostic = next
				res.Hops = append(res.Hops, Hop{AliasID: spec.ID, WM: spec.WM, From: cur, To: next, BoundaryTenant: spec.BoundaryTenant})
				return res
			}
		}

		res.Hops = append(res.Hops, Hop{
			AliasID:        spec.ID,
			WM:             spec.WM,
			From:           cur,
			To:             next,
			BoundaryTenant: spec.BoundaryTenant,
		})
		cur = next
	}

	res.Code = CodeCycle
	res.Message = "alias chain exceeded maximum hop count"
	res.Diagnostic = cur
	return res
}

// resolveLatest performs a cycle-guarded rewrite using the newest operation of
// every alias, ignoring boundary checks. Diagnostic only.
func (t *Table) resolveLatest(cur winpath.Key) winpath.Key {
	seen := map[winpath.Key]bool{}
	for hop := 0; hop < maxHops; hop++ {
		prefix, vs, known := t.KnownPrefix(cur)
		if !known {
			return cur
		}
		latest, ok := latestOp(vs)
		if !ok || latest.Op == OpRemove {
			return ""
		}
		if seen[cur] {
			return cur
		}
		seen[cur] = true
		rest, _ := winpath.StripPrefix(cur, prefix)
		cur = winpath.ApplyPrefix(latest.Target, rest)
	}
	return cur
}

func latestOp(vs []Spec) (Spec, bool) {
	if len(vs) == 0 {
		return Spec{}, false
	}
	// Versions are sorted ascending; still guard order assumptions.
	best := vs[0]
	for _, s := range vs[1:] {
		if s.WM > best.WM || (s.WM == best.WM && s.Seq > best.Seq) {
			best = s
		}
	}
	return best, true
}

func aliasID(vs []Spec) string {
	if s, ok := latestOp(vs); ok {
		return s.ID
	}
	return "?"
}

// ResolveAtHead is a convenience resolving at an effectively infinite
// watermark (newest committed state).
func (t *Table) ResolveAtHead(cur winpath.Key, tm *tenant.Map) Result {
	return t.Resolve(cur, math.MaxInt32, tm)
}
