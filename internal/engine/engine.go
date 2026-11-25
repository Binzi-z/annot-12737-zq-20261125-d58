// Package engine performs the offline quarantine-reference audit: it replays
// the synthetic arrival stream, canonicalizes logical paths, resolves
// watermark-versioned aliases, follows active renames, honors undo-sync
// revocation, and builds verifiable chains plus the minimal non-recyclable set.
package engine

import (
	"fmt"
	"sort"
	"strings"

	"quaraudit/internal/alias"
	"quaraudit/internal/model"
	"quaraudit/internal/report"
	"quaraudit/internal/tenant"
	"quaraudit/internal/winpath"
)

// extra engine-side reason codes (alias codes live in internal/alias).
const reasonRenameCycle = "RENAME_CYCLE"

type logicalNode struct {
	key     winpath.Key
	display string
	ids     []string
	primary string
	tenant  string
}

type renameCall struct {
	oldKey winpath.Key
	newKey winpath.Key
	batch  string
	seq    int
}

type fstate struct {
	node       *logicalNode
	held       bool
	witnesses  []string
	chainIDs   []string
	blocked    bool
	reasonCode string
	reasonMsg  string
	blockRecs  []string
}

type recordEnvelope struct {
	rec   *model.Record
	wm    int
	batch string
}

type auditor struct {
	c   *model.Case
	rep *report.Report
	tm  *tenant.Map

	nodes  []*logicalNode
	byKey  map[winpath.Key]*logicalNode
	states map[winpath.Key]*fstate

	undone        map[string]bool
	activeRename  map[winpath.Key]winpath.Key
	revokedRename map[winpath.Key]renameCall

	table   *alias.Table
	records []recordEnvelope

	// normalized events stashed for the post-undo build step
	aliasSpecs []alias.Spec
	renames    []renameCall
}

// Audit runs the audit over a decoded Case.
func Audit(c *model.Case) (*report.Report, error) {
	a := &auditor{
		c:             c,
		rep:           &report.Report{Schema: report.Schema, CaseID: c.CaseID, Title: c.Title},
		byKey:         map[winpath.Key]*logicalNode{},
		states:        map[winpath.Key]*fstate{},
		undone:        map[string]bool{},
		activeRename:  map[winpath.Key]winpath.Key{},
		revokedRename: map[winpath.Key]renameCall{},
	}
	a.rep.MinimalNonRecyclable = []report.HeldFile{}
	a.rep.BlockedPendingEvidence = []report.BlockedFile{}
	a.rep.Recyclable = []report.RecyclableFile{}
	a.rep.Files = []report.FileVerdict{}
	a.rep.Chains = []report.Chain{}
	a.rep.RecordResults = []report.RecordResult{}
	a.rep.BoundaryViolations = []report.BoundaryViolation{}
	a.rep.Warnings = []string{}

	qp, err := winpath.Normalize(c.QuarantineRoot)
	if err != nil {
		return nil, fmt.Errorf("quarantine_root: %w", err)
	}
	a.rep.QuarantineRoot = qp.Display
	if c.OwnerSandbox == "" {
		return nil, fmt.Errorf("owner_sandbox is required")
	}
	a.rep.OwnerSandbox = c.OwnerSandbox

	// Tenant roots.
	var troots []tenant.Root
	for i, tr := range c.TenantRoots {
		p, err := winpath.Normalize(tr.Root)
		if err != nil {
			return nil, fmt.Errorf("tenant_roots[%d] (%s): %w", i, tr.Tenant, err)
		}
		troots = append(troots, tenant.Root{Tenant: tr.Tenant, Root: p.Key})
	}
	a.tm = tenant.NewMap(troots...)

	if err := a.loadFiles(qp); err != nil {
		return nil, err
	}
	if err := a.processEvents(); err != nil {
		return nil, err
	}

	specs := a.collectAliasSpecs()
	a.table = alias.NewTable(specs)

	a.buildRenameMaps()
	a.evaluateRecords()
	a.buildOutputs()

	return a.rep, nil
}

func (a *auditor) loadFiles(qp winpath.Path) error {
	for i, f := range a.c.Files {
		if strings.TrimSpace(f.ID) == "" {
			return fmt.Errorf("files[%d]: id is required", i)
		}
		p, err := winpath.Normalize(f.Path)
		if err != nil {
			return fmt.Errorf("files[%d] %s: %w", i, f.ID, err)
		}
		if n, ok := a.byKey[p.Key]; ok {
			n.ids = append(n.ids, f.ID)
			a.rep.Summary.MergedDuplicateRows++
			if f.Tenant != "" && n.tenant == "" {
				n.tenant = f.Tenant
			}
			continue
		}
		ten := f.Tenant
		if ten == "" {
			ten = a.tm.TenantOf(p.Key)
		}
		n := &logicalNode{key: p.Key, display: p.Display, ids: []string{f.ID}, primary: f.ID, tenant: ten}
		a.byKey[p.Key] = n
		a.nodes = append(a.nodes, n)
		a.states[p.Key] = &fstate{node: n}

		if !winpath.HasSegmentPrefix(p.Key, qp.Key) {
			a.rep.Warnings = append(a.rep.Warnings,
				fmt.Sprintf("file %s (%s) is outside quarantine_root %s", f.ID, p.Display, qp.Display))
		}
	}
	a.rep.Summary.RetainedInputRows = len(a.c.Files)
	a.rep.Summary.LogicalFiles = len(a.nodes)
	return nil
}

func (a *auditor) processEvents() error {
	var specs []alias.Spec
	var renames []renameCall

	for i, ev := range a.c.Events {
		seq := ev.Seq
		if seq == 0 {
			seq = i + 1
		}
		switch ev.Type {
		case model.EvUndoSync:
			ub := ev.UndoBatch
			if ub == "" {
				ub = ev.Batch
			}
			if ub == "" {
				return fmt.Errorf("events[%d] undo_sync requires undo_batch", i)
			}
			a.undone[ub] = true

		case model.EvAliasUpsert, model.EvAliasRemove:
			ap, err := winpath.Normalize(ev.Alias)
			if err != nil {
				return fmt.Errorf("events[%d] alias %q: %w", i, ev.AliasID, err)
			}
			sp := alias.Spec{
				ID:             ev.AliasID,
				WM:             ev.WM,
				Seq:            seq,
				Alias:          ap.Key,
				BoundaryTenant: ev.BoundaryTenant,
			}
			if ev.Type == model.EvAliasRemove {
				sp.Op = alias.OpRemove
			} else {
				sp.Op = alias.OpUpsert
				tp, err := winpath.Normalize(ev.Target)
				if err != nil {
					return fmt.Errorf("events[%d] alias %q target: %w", i, ev.AliasID, err)
				}
				sp.Target = tp.Key
				if strings.TrimSpace(ev.Scope) != "" {
					sc, err := winpath.Normalize(ev.Scope)
					if err != nil {
						return fmt.Errorf("events[%d] alias %q scope: %w", i, ev.AliasID, err)
					}
					sp.Scope = sc.Key
				}
			}
			if sp.ID == "" {
				sp.ID = fmt.Sprintf("ALIAS@%s-wm%d", ap.Key, ev.WM)
			}
			specs = append(specs, sp)

		case model.EvRename:
			op, err := winpath.Normalize(ev.OldPath)
			if err != nil {
				return fmt.Errorf("events[%d] rename old_path: %w", i, err)
			}
			np, err := winpath.Normalize(ev.NewPath)
			if err != nil {
				return fmt.Errorf("events[%d] rename new_path: %w", i, err)
			}
			renames = append(renames, renameCall{oldKey: op.Key, newKey: np.Key, batch: ev.Batch, seq: seq})

		case model.EvReference:
			if ev.Record == nil {
				return fmt.Errorf("events[%d] reference requires a record object", i)
			}
			wm := ev.Record.WM
			if wm == 0 {
				wm = ev.WM
			}
			batch := ev.Record.Batch
			if batch == "" {
				batch = ev.Batch
			}
			a.records = append(a.records, recordEnvelope{rec: ev.Record, wm: wm, batch: batch})

		default:
			return fmt.Errorf("events[%d]: unknown event type %q", i, ev.Type)
		}
	}

	// Stash for the post-undo build step.
	a.aliasSpecs = specs
	a.renames = renames
	return nil
}

func (a *auditor) collectAliasSpecs() []alias.Spec { return a.aliasSpecs }

func (a *auditor) buildRenameMaps() {
	for _, rn := range a.renames {
		if rn.batch != "" && a.undone[rn.batch] {
			// Revoked rename: keep separately so a claim through the old name
			// gets an explicit RENAME_BATCH_UNDONE break rather than a silent
			// miss. An active rename for the same old name wins if present.
			if _, active := a.activeRename[rn.oldKey]; !active {
				a.revokedRename[rn.oldKey] = rn
			}
			continue
		}
		a.activeRename[rn.oldKey] = rn.newKey
	}
}

func (a *auditor) evaluateRecords() {
	a.rep.Summary.RecordsTotal = len(a.records)
	for _, env := range a.records {
		a.evaluateOne(env)
	}
}

func (a *auditor) evaluateOne(env recordEnvelope) {
	rec := env.rec
	rr := report.RecordResult{RecordID: rec.ID, ChainIDs: []string{}, MatchedFileIDs: []string{}}
	variant := 0

	mkChain := func(status string) *report.Chain {
		variant++
		return &report.Chain{
			ChainID:       fmt.Sprintf("CH-%s-%d", rec.ID, variant),
			RecordID:      rec.ID,
			Status:        status,
			SourceSandbox: rec.Sandbox,
			SourceTenant:  rec.Tenant,
			Links: []report.Link{{
				Kind:   report.LinkRecord,
				Detail: fmt.Sprintf("synthetic reference record %s from sandbox %s", rec.ID, rec.Sandbox),
			}},
		}
	}
	finish := func(ch *report.Chain) {
		rr.ChainIDs = append(rr.ChainIDs, ch.ChainID)
		a.rep.Chains = append(a.rep.Chains, *ch)
	}
	breakOut := func(ch *report.Chain, code, msg string) {
		ch.Status = report.RecBroken
		ch.ReasonCode = code
		ch.ReasonMessage = msg
		ch.Links = append(ch.Links, report.Link{Kind: report.LinkTerminal, Detail: "chain broken: " + code})
		rr.Status = report.RecBroken
		rr.ReasonCode = code
		rr.ReasonMessage = msg
		finish(ch)
		a.rep.RecordResults = append(a.rep.RecordResults, rr)
	}

	// 1) Undo-sync revocation removes the assertion itself.
	if env.batch != "" && a.undone[env.batch] {
		ch := mkChain(report.RecRevoked)
		ch.Status = report.RecRevoked
		msg := fmt.Sprintf("record arrived in sync batch %q which was revoked by undo_sync", env.batch)
		ch.ReasonCode = report.ReasonRecordUndone
		ch.ReasonMessage = msg
		ch.Links = append(ch.Links, report.Link{Kind: report.LinkTerminal, Detail: msg})
		rr.Status = report.RecRevoked
		rr.ReasonCode = report.ReasonRecordUndone
		rr.ReasonMessage = msg
		finish(ch)
		a.rep.RecordResults = append(a.rep.RecordResults, rr)
		return
	}

	// 2) Logical normalization of the raw path.
	np, err := winpath.Normalize(rec.RawPath)
	if err != nil {
		ch := mkChain(report.RecBroken)
		breakOut(ch, report.ReasonPathMalformed, err.Error())
		return
	}
	key := np.Key
	baseLinks := []report.Link{{
		Kind:   report.LinkNormalize,
		From:   rec.RawPath,
		To:     np.Display,
		Detail: "drive-case/separator/whitespace canonicalization -> " + string(np.Key),
	}}

	// 3) Watermark-correct alias resolution.
	ar := a.table.Resolve(key, env.wm, a.tm)
	for _, h := range ar.Hops {
		baseLinks = append(baseLinks, report.Link{
			Kind: report.LinkAlias, AliasID: h.AliasID, WM: h.WM,
			From: string(h.From), To: string(h.To),
			Detail: fmt.Sprintf("reparse alias %s active at watermark %d", h.AliasID, h.WM),
		})
	}
	if !ar.OK {
		ch := mkChain(report.RecBroken)
		ch.Links = append(ch.Links, baseLinks...)
		var tied *logicalNode
		if ar.Diagnostic != "" {
			tied = a.byKey[ar.Diagnostic]
			if tied != nil {
				ch.FileID = tied.primary
			}
		}
		if tied != nil {
			a.markBlocked(tied, ar.Code, ar.Message, rec.ID)
		}
		if ar.Code == alias.CodeTenantCross || ar.Code == alias.CodeScopeEscape {
			fid := ""
			if tied != nil {
				fid = tied.primary
			}
			a.rep.BoundaryViolations = append(a.rep.BoundaryViolations, report.BoundaryViolation{
				RecordID: rec.ID, FileID: fid, Kind: ar.Code, Detail: ar.Message,
			})
		}
		breakOut(ch, ar.Code, ar.Message)
		return
	}
	key = ar.Final

	// 4) Active rename forwarding.
	seenRename := map[winpath.Key]bool{}
	for {
		nk, ok := a.activeRename[key]
		if !ok {
			break
		}
		if seenRename[key] {
			ch := mkChain(report.RecBroken)
			ch.Links = append(ch.Links, baseLinks...)
			breakOut(ch, reasonRenameCycle, "rename graph cycle at "+string(key))
			return
		}
		seenRename[key] = true
		baseLinks = append(baseLinks, report.Link{
			Kind: report.LinkRename, From: string(key), To: string(nk),
			Detail: "forwarded across an active rename arrival",
		})
		key = nk
	}

	// 5) Inventory matching (exact file or segment-subtree for tree refs).
	kind := rec.Kind
	if kind == "" {
		kind = model.KindFile
	}
	var cands []*logicalNode
	matchLinkKind := report.LinkMatch
	if kind == model.KindTree {
		matchLinkKind = report.LinkPrefixMatch
		for _, n := range a.nodes {
			if rest, ok := winpath.StripPrefix(n.key, key); ok && len(rest) > 0 {
				cands = append(cands, n)
			}
		}
	} else if n, ok := a.byKey[key]; ok {
		cands = []*logicalNode{n}
	}

	if len(cands) == 0 {
		// A revoked rename is the verifiable explanation for the miss.
		if rc, wasRevoked := a.revokedRename[key]; wasRevoked {
			msg := fmt.Sprintf("path only forwards via a rename from batch %q that undo_sync revoked", rc.batch)
			ch := mkChain(report.RecBroken)
			ch.Links = append(ch.Links, baseLinks...)
			ch.Links = append(ch.Links, report.Link{Kind: report.LinkRenameRevoked, From: string(rc.oldKey), To: string(rc.newKey), Detail: msg})
			if n, ok := a.byKey[rc.newKey]; ok {
				ch.FileID = n.primary
				a.markBlocked(n, report.ReasonRenameUndone, msg, rec.ID)
			}
			breakOut(ch, report.ReasonRenameUndone, msg)
			return
		}
		ch := mkChain(report.RecBroken)
		ch.Links = append(ch.Links, baseLinks...)
		breakOut(ch, report.ReasonTargetMissing,
			"resolved logical target "+string(key)+" matches no retained file (record may be stale or point outside quarantine)")
		return
	}

	// 6) Classify every matched candidate: self / tenant-cross / complete.
	sawComplete, sawTenantBreak, sawSelf := false, false, false
	var firstBreakCode, firstBreakMsg string
	for _, n := range cands {
		ch := mkChain(report.RecComplete)
		ch.Links = append(ch.Links, baseLinks...)
		ch.FileID = n.primary
		ch.MatchKind = kind
		ch.Links = append(ch.Links, report.Link{
			Kind: matchLinkKind, From: string(key), To: n.display,
			Detail: "resolved logical target matches retained object " + n.primary,
		})

		switch {
		case rec.Sandbox != "" && rec.Sandbox == a.c.OwnerSandbox:
			ch.Status = report.RecSelf
			ch.ReasonCode = report.ReasonSelfSandbox
			ch.ReasonMessage = "reference originates from the quarantine-owning sandbox, not another sandbox"
			ch.Links = append(ch.Links, report.Link{Kind: report.LinkTerminal, Detail: ch.ReasonMessage})
			sawSelf = true

		case n.tenant != "" && rec.Tenant != "" && n.tenant != rec.Tenant:
			code := alias.CodeTenantCross
			msg := fmt.Sprintf("record sandbox tenant %q may not hold a live reference to retained file tenant %q", rec.Tenant, n.tenant)
			ch.Status = report.RecBroken
			ch.ReasonCode = code
			ch.ReasonMessage = msg
			ch.Links = append(ch.Links, report.Link{Kind: report.LinkTenantCheck, Detail: msg})
			ch.Links = append(ch.Links, report.Link{Kind: report.LinkTerminal, Detail: "chain broken: " + code})
			a.markBlocked(n, code, msg, rec.ID)
			a.rep.BoundaryViolations = append(a.rep.BoundaryViolations, report.BoundaryViolation{
				RecordID: rec.ID, FileID: n.primary, Kind: code, Detail: msg,
			})
			sawTenantBreak = true
			if firstBreakCode == "" {
				firstBreakCode, firstBreakMsg = code, msg
			}

		default:
			ch.Status = report.RecComplete
			ch.Links = append(ch.Links, report.Link{Kind: report.LinkTerminal, Detail: "external sandbox reference verified end to end"})
			a.markHeld(n, rec.ID, ch.ChainID)
			rr.MatchedFileIDs = append(rr.MatchedFileIDs, n.primary)
			sawComplete = true
		}

		finish(ch)
	}

	switch {
	case sawComplete:
		rr.Status = report.RecComplete
	case sawTenantBreak:
		rr.Status = report.RecBroken
		rr.ReasonCode = firstBreakCode
		rr.ReasonMessage = firstBreakMsg
	case sawSelf:
		rr.Status = report.RecSelf
		rr.ReasonCode = report.ReasonSelfSandbox
	default:
		rr.Status = report.RecBroken
	}
	a.rep.RecordResults = append(a.rep.RecordResults, rr)
}

func (a *auditor) markHeld(n *logicalNode, recID, chainID string) {
	st := a.states[n.key]
	st.held = true
	if !contains(st.witnesses, recID) {
		st.witnesses = append(st.witnesses, recID)
	}
	if !contains(st.chainIDs, chainID) {
		st.chainIDs = append(st.chainIDs, chainID)
	}
}

func (a *auditor) markBlocked(n *logicalNode, code, msg, recID string) {
	st := a.states[n.key]
	st.blocked = true
	if st.reasonCode == "" {
		st.reasonCode = code
		st.reasonMsg = msg
	}
	if !contains(st.blockRecs, recID) {
		st.blockRecs = append(st.blockRecs, recID)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// buildOutputs materializes sorted report sections and summary counts.
func (a *auditor) buildOutputs() {
	for _, n := range a.nodes {
		st := a.states[n.key]
		fv := report.FileVerdict{
			FileID: n.primary, AllFileIDs: n.ids, LogicalKey: string(n.key),
			DisplayPath: n.display, Tenant: n.tenant,
		}
		switch {
		case st.held:
			fv.Verdict = report.VerdictHeld
			fv.WitnessRecords = append([]string{}, st.witnesses...)
			a.rep.Summary.Held++
			a.rep.MinimalNonRecyclable = append(a.rep.MinimalNonRecyclable, report.HeldFile{
				FileID: n.primary, AllFileIDs: n.ids, LogicalKey: string(n.key), DisplayPath: n.display,
				Tenant: n.tenant, WitnessRecords: append([]string{}, st.witnesses...),
				ChainIDs: append([]string{}, st.chainIDs...),
			})
		case st.blocked:
			fv.Verdict = report.VerdictBlocked
			fv.ReasonCode = st.reasonCode
			fv.BlockingRecords = append([]string{}, st.blockRecs...)
			a.rep.Summary.Blocked++
			a.rep.BlockedPendingEvidence = append(a.rep.BlockedPendingEvidence, report.BlockedFile{
				FileID: n.primary, LogicalKey: string(n.key), DisplayPath: n.display,
				ReasonCode: st.reasonCode, ReasonMessage: st.reasonMsg,
				ClaimRecords: append([]string{}, st.blockRecs...),
			})
		default:
			fv.Verdict = report.VerdictFree
			a.rep.Summary.Free++
			a.rep.Recyclable = append(a.rep.Recyclable, report.RecyclableFile{
				FileID: n.primary, LogicalKey: string(n.key), DisplayPath: n.display,
				Reason: "no active external reference chain",
			})
		}
		a.rep.Files = append(a.rep.Files, fv)
	}

	// Record status counts.
	for _, rr := range a.rep.RecordResults {
		switch rr.Status {
		case report.RecComplete:
			a.rep.Summary.RecordsComplete++
		case report.RecBroken:
			a.rep.Summary.RecordsBroken++
		case report.RecRevoked:
			a.rep.Summary.RecordsRevoked++
		case report.RecSelf:
			a.rep.Summary.RecordsSelf++
		}
	}
	a.rep.Summary.ChainsTotal = len(a.rep.Chains)
	for _, ch := range a.rep.Chains {
		if ch.Status == report.RecComplete {
			a.rep.Summary.ChainsComplete++
		}
	}
	a.rep.Summary.BoundaryViolations = len(a.rep.BoundaryViolations)

	// Deterministic ordering of violation list (already record order) and
	// stable sorting of warnings.
	sort.Strings(a.rep.Warnings)
}
