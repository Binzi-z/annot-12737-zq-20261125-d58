// Package tenant maps canonical logical paths to tenant identifiers using
// longest segment-prefix roots. It is the offline oracle for tenant-boundary
// checks.
package tenant

import (
	"sort"

	"quaraudit/internal/winpath"
)

// Root associates a tenant with a canonical path root.
type Root struct {
	Tenant string      `json:"tenant"`
	Root   winpath.Key `json:"root"`
}

// Map is a longest-prefix tenant lookup.
type Map struct {
	roots []Root // sorted by segment depth descending for longest match
}

// NewMap builds a Map from tenant roots.
func NewMap(roots ...Root) *Map {
	m := &Map{roots: make([]Root, len(roots))}
	copy(m.roots, roots)
	sort.SliceStable(m.roots, func(i, j int) bool {
		return len(m.roots[i].Root.Segments()) > len(m.roots[j].Root.Segments())
	})
	return m
}

// TenantOf returns the tenant whose root is the longest segment prefix of k.
// Returns "" when no root matches.
func (m *Map) TenantOf(k winpath.Key) string {
	if m == nil {
		return ""
	}
	for _, r := range m.roots {
		if winpath.HasSegmentPrefix(k, r.Root) {
			return r.Tenant
		}
	}
	return ""
}
