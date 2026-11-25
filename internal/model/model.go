// Package model defines the synthetic, offline audit input format.
//
// Every input is logical data only: paths are strings and reference records are
// synthetic. The audit never inspects a real directory.
package model

// Case is the top-level audit input document.
type Case struct {
	SchemaVersion  string            `json:"schema_version"`
	CaseID         string            `json:"case_id"`
	Title          string            `json:"title,omitempty"`
	QuarantineRoot string            `json:"quarantine_root"`
	OwnerSandbox   string            `json:"owner_sandbox"`
	TenantRoots    []TenantRootInput `json:"tenant_roots,omitempty"`
	Files          []FileInput       `json:"files"`
	Events         []Event           `json:"events"`
}

// TenantRootInput is one tenant path root.
type TenantRootInput struct {
	Tenant string `json:"tenant"`
	Root   string `json:"root"`
}

// FileInput is one retained-object inventory row. Rows that canonicalize to
// the same logical path are merged into one logical file by the engine.
type FileInput struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Tenant string `json:"tenant,omitempty"`
}

// Event is one arrival in the synthetic sync stream. Only the fields relevant
// to Type are used. Seq is arrival order; WM is the logical watermark.
type Event struct {
	Type  string `json:"type"`
	Seq   int    `json:"seq,omitempty"`
	WM    int    `json:"wm,omitempty"`
	Batch string `json:"batch,omitempty"`

	// alias_upsert / alias_remove
	AliasID        string `json:"alias_id,omitempty"`
	Alias          string `json:"alias,omitempty"`
	Target         string `json:"target,omitempty"`
	BoundaryTenant string `json:"boundary_tenant,omitempty"`
	Scope          string `json:"scope,omitempty"`

	// rename
	OldPath string `json:"old_path,omitempty"`
	NewPath string `json:"new_path,omitempty"`

	// undo_sync: names the batch whose arrivals are revoked
	UndoBatch string `json:"undo_batch,omitempty"`

	// reference arrival
	Record *Record `json:"record,omitempty"`
}

// Event type constants.
const (
	EvAliasUpsert = "alias_upsert"
	EvAliasRemove = "alias_remove"
	EvRename      = "rename"
	EvUndoSync    = "undo_sync"
	EvReference   = "reference"
)

// Record is one synthetic "another sandbox references this path" assertion.
type Record struct {
	ID      string `json:"id"`
	Sandbox string `json:"sandbox"`
	Tenant  string `json:"tenant,omitempty"`
	RawPath string `json:"raw_path"`
	WM      int    `json:"wm,omitempty"`
	Batch   string `json:"batch,omitempty"`
	Kind    string `json:"kind,omitempty"` // "file" (default) or "tree"
}

// Reference kind constants.
const (
	KindFile = "file"
	KindTree = "tree"
)
