// Package synth generates deterministic, fully synthetic audit worlds for
// scale and boundary testing. It performs no filesystem I/O.
//
// The 50k world lays out five tenants and, inside tenant t00, an aliased
// "green" subtree plus deliberately confusing sibling directories
// ("green2", "green-backup") whose names naive string-prefix rewrites would
// leak into. Every generated path is unique.
package synth

import (
	"fmt"
	"strings"

	"quaraudit/internal/alias"
	"quaraudit/internal/model"
	"quaraudit/internal/winpath"
)

// ScaleWorld holds a generated world plus the coordinates the boundary test
// needs to build old/new/cross-tenant alias tables and an independent oracle.
type ScaleWorld struct {
	N int

	Case *model.Case

	// Alias coordinates (canonical).
	AliasKey       winpath.Key
	OldTarget      winpath.Key
	NewTarget      winpath.Key
	CrossTarget    winpath.Key
	BoundaryTenant string
	Watermark      int

	// Per-file aligned arrays (length N).
	FileKeys   []winpath.Key
	FileTenant []string
	RawAccess  []string

	// Indices whose raw access path lives below the alias segment prefix.
	AliasAccessIndices []int
	// Indices of the prefix-trap sibling files.
	TrapIndices []int
	// Indices of ordinary other-tenant files.
	OtherTenantIndices []int
}

// BuildScale generates exactly n unique retained files. n must be a positive
// multiple of 5; the scale test uses 50000.
func BuildScale(n int) *ScaleWorld {
	if n <= 0 || n%5 != 0 {
		panic("BuildScale: n must be a positive multiple of 5")
	}
	per := n / 5
	w := &ScaleWorld{
		N:              n,
		FileKeys:       make([]winpath.Key, 0, n),
		FileTenant:     make([]string, 0, n),
		RawAccess:      make([]string, 0, n),
		BoundaryTenant: "t00",
		Watermark:      5,
	}

	w.AliasKey = winpath.MustKey(`V:\tenants\t00\mnt\green`)
	w.OldTarget = winpath.MustKey(`V:\tenants\t00\data\green`)
	w.NewTarget = winpath.MustKey(`V:\tenants\t00\data\blue`)
	w.CrossTarget = winpath.MustKey(`V:\tenants\t01\data\intrude`)

	c := &model.Case{
		SchemaVersion:  "quaraudit.case/v1",
		CaseID:         "SCALE-50K",
		Title:          "五万文件换别名边界压测",
		QuarantineRoot: `V:\`,
		OwnerSandbox:   "SBX-QUAR",
		TenantRoots: []model.TenantRootInput{
			{Tenant: "t00", Root: `V:\tenants\t00`},
			{Tenant: "t01", Root: `V:\tenants\t01`},
			{Tenant: "t02", Root: `V:\tenants\t02`},
			{Tenant: "t03", Root: `V:\tenants\t03`},
			{Tenant: "t04", Root: `V:\tenants\t04`},
		},
	}

	addFile := func(tenant, physicalRaw, accessRaw string, isAlias, isTrap, otherTenant bool) {
		fi := len(c.Files)
		id := fmt.Sprintf("F%05d", fi)
		c.Files = append(c.Files, model.FileInput{ID: id, Path: physicalRaw, Tenant: tenant})
		fk := winpath.MustKey(physicalRaw)
		w.FileKeys = append(w.FileKeys, fk)
		w.FileTenant = append(w.FileTenant, tenant)
		w.RawAccess = append(w.RawAccess, noise(fi, accessRaw))
		if isAlias {
			w.AliasAccessIndices = append(w.AliasAccessIndices, fi)
		}
		if isTrap {
			w.TrapIndices = append(w.TrapIndices, fi)
		}
		if otherTenant {
			w.OtherTenantIndices = append(w.OtherTenantIndices, fi)
		}
	}

	for t := 0; t < 5; t++ {
		ten := fmt.Sprintf("t%02d", t)
		root := fmt.Sprintf(`V:\tenants\%s`, ten)
		for j := 0; j < per; j++ {
			switch {
			case t == 0 && j < 2000:
				// Green physical subtree; exposed through AL-GREEN.
				name := fmt.Sprintf("g_%05d.dat", j)
				phys := root + `\data\green\` + name
				access := root + `\mnt\green\` + name
				addFile(ten, phys, access, true, false, false)

			case t == 0 && j < 4000:
				name := fmt.Sprintf("b_%05d.dat", j-2000)
				phys := root + `\data\blue\` + name
				// Blue files are accessed directly (the re-point target).
				addFile(ten, phys, phys, false, false, false)

			case t == 0 && j < 4500:
				name := fmt.Sprintf("two_%05d.dat", j-4000)
				phys := root + `\mnt\green2\` + name
				addFile(ten, phys, phys, false, true, false)

			case t == 0 && j < 5000:
				name := fmt.Sprintf("bk_%05d.dat", j-4500)
				phys := root + `\mnt\green-backup\` + name
				addFile(ten, phys, phys, false, true, false)

			case t == 0:
				name := fmt.Sprintf("o_%05d.dat", j-5000)
				dir := fmt.Sprintf(`\ord\dir_%02d\`, (j-5000)%50)
				phys := root + dir + name
				addFile(ten, phys, phys, false, false, false)

			default:
				name := fmt.Sprintf("o_%05d.dat", j)
				dir := fmt.Sprintf(`\ord\dir_%03d\`, j%100)
				phys := root + dir + name
				addFile(ten, phys, phys, false, false, true)
			}
		}
	}

	// The single alias under test (old target). The boundary tenant is pinned
	// to t00 so a re-point into t01 is denied by the resolver.
	c.Events = append(c.Events, model.Event{
		Type: model.EvAliasUpsert, Seq: 1, WM: 1, AliasID: "AL-GREEN",
		Alias:          `V:\Tenants\T00\MNT\Green`, // mixed case on purpose
		Target:         string(w.OldTarget),
		BoundaryTenant: w.BoundaryTenant,
	})

	w.Case = c
	return w
}

// AliasSpec builds the version-1 spec for AL-GREEN pointing at target.
func (w *ScaleWorld) AliasSpec(target winpath.Key) alias.Spec {
	return alias.Spec{
		ID:             "AL-GREEN",
		Op:             alias.OpUpsert,
		WM:             1,
		Seq:            1,
		Alias:          w.AliasKey,
		Target:         target,
		BoundaryTenant: w.BoundaryTenant,
	}
}

// AddSampledReferences appends one exact external reference every step files
// (each from its own tenant sandbox) using the noisy RawAccess spellings.
// Returns the number added and the selected file indices.
func (w *ScaleWorld) AddSampledReferences(step int) (int, []int) {
	if step <= 0 {
		step = 20
	}
	selected := []int{}
	seq := 100
	for i := 0; i < w.N; i += step {
		ten := w.FileTenant[i]
		sandbox := "SBX-" + ten
		w.Case.Events = append(w.Case.Events, model.Event{
			Type: model.EvReference, Seq: seq,
			Record: &model.Record{
				ID:      fmt.Sprintf("REF-%05d", i),
				Sandbox: sandbox,
				Tenant:  ten,
				WM:      w.Watermark,
				Kind:    model.KindFile,
				RawPath: w.RawAccess[i],
			},
		})
		selected = append(selected, i)
		seq++
	}
	return len(selected), selected
}

// noise applies deterministic, identity-preserving spelling variation so the
// scale run actually exercises normalization at volume: slash swaps, duplicated
// separators, drive case and outer whitespace.
func noise(i int, s string) string {
	if i%11 == 0 {
		// Duplicate the separator around the "tenants" segment.
		s = strings.Replace(s, `\tenants\`, `\\tenants\\`, 1)
	}
	if i%5 == 0 {
		s = strings.ReplaceAll(s, `\`, `/`)
	}
	if i%7 == 0 && len(s) >= 2 {
		s = strings.ToLower(s[:1]) + s[1:]
	}
	if i%13 == 0 {
		s = "  " + s + " \t"
	}
	return s
}
