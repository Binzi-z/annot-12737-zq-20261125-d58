// Package report defines the stable JSON report schema emitted by the audit
// engine and consumed by the independent verifier.
package report

// Schema is the wire-format identifier.
const Schema = "quaraudit.report/v1"

// File verdicts.
const (
	// VerdictHeld: at least one complete external reference chain proves the
	// logical file is still referenced by another sandbox. Member of the
	// minimal non-recyclable set.
	VerdictHeld = "HELD"
	// VerdictBlocked: an active reference-shaped claim exists but its chain is
	// broken for an evidentiary/boundary reason. Not counted in the minimal
	// proven set; recycling must wait for investigation.
	VerdictBlocked = "BLOCKED"
	// VerdictFree: no active external claim survives.
	VerdictFree = "FREE"
)

// Per-record outcome statuses.
const (
	RecComplete = "COMPLETE"
	RecBroken   = "BROKEN"
	RecRevoked  = "REVOKED"
	RecSelf     = "SELF_ONLY"
)

// Blocking / break reason codes. Alias resolver codes are reused verbatim from
// internal/alias; the engine adds the codes below.
const (
	ReasonRecordUndone  = "RECORD_BATCH_UNDONE"
	ReasonRenameUndone  = "RENAME_BATCH_UNDONE"
	ReasonPathMalformed = "PATH_MALFORMED"
	ReasonTargetMissing = "TARGET_NOT_RETAINED"
	ReasonSelfSandbox   = "SELF_SANDBOX_REFERENCE"
)

// Link kinds inside a reference chain.
const (
	LinkRecord        = "record"
	LinkNormalize     = "normalize"
	LinkAlias         = "alias_reparse"
	LinkRename        = "rename_forward"
	LinkRenameRevoked = "rename_revoked"
	LinkTenantCheck   = "tenant_check"
	LinkMatch         = "inventory_match"
	LinkPrefixMatch   = "inventory_prefix_match"
	LinkTerminal      = "terminal"
)

// Report is the top-level audit result.
type Report struct {
	Schema                 string              `json:"schema"`
	CaseID                 string              `json:"case_id"`
	Title                  string              `json:"title,omitempty"`
	QuarantineRoot         string              `json:"quarantine_root"`
	OwnerSandbox           string              `json:"owner_sandbox"`
	Summary                Summary             `json:"summary"`
	MinimalNonRecyclable   []HeldFile          `json:"minimal_non_recyclable"`
	BlockedPendingEvidence []BlockedFile       `json:"blocked_pending_evidence"`
	Recyclable             []RecyclableFile    `json:"recyclable"`
	Files                  []FileVerdict       `json:"files"`
	Chains                 []Chain             `json:"chains"`
	RecordResults          []RecordResult      `json:"record_results"`
	BoundaryViolations     []BoundaryViolation `json:"boundary_violations"`
	Warnings               []string            `json:"warnings,omitempty"`
}

// Summary holds counts.
type Summary struct {
	RetainedInputRows   int `json:"retained_input_rows"`
	LogicalFiles        int `json:"logical_files"`
	MergedDuplicateRows int `json:"merged_duplicate_rows"`

	Held    int `json:"held"`
	Blocked int `json:"blocked"`
	Free    int `json:"free"`

	RecordsTotal    int `json:"records_total"`
	RecordsComplete int `json:"records_complete"`
	RecordsBroken   int `json:"records_broken"`
	RecordsRevoked  int `json:"records_revoked"`
	RecordsSelf     int `json:"records_self_only"`

	ChainsTotal    int `json:"chains_total"`
	ChainsComplete int `json:"chains_complete"`

	BoundaryViolations int `json:"boundary_violations"`
}

// HeldFile is one member of the minimal non-recyclable set.
type HeldFile struct {
	FileID         string   `json:"file_id"`
	AllFileIDs     []string `json:"all_file_ids,omitempty"`
	LogicalKey     string   `json:"logical_key"`
	DisplayPath    string   `json:"display_path"`
	Tenant         string   `json:"tenant,omitempty"`
	WitnessRecords []string `json:"witness_records"`
	ChainIDs       []string `json:"chain_ids"`
}

// BlockedFile explains an evidence gap with an explicit blocking reason.
type BlockedFile struct {
	FileID        string   `json:"file_id"`
	LogicalKey    string   `json:"logical_key"`
	DisplayPath   string   `json:"display_path"`
	ReasonCode    string   `json:"reason_code"`
	ReasonMessage string   `json:"reason_message,omitempty"`
	ClaimRecords  []string `json:"claim_records"`
}

// RecyclableFile is a logical file with no surviving external claim.
type RecyclableFile struct {
	FileID      string `json:"file_id"`
	LogicalKey  string `json:"logical_key"`
	DisplayPath string `json:"display_path"`
	Reason      string `json:"reason"`
}

// FileVerdict is the per-logical-file row.
type FileVerdict struct {
	FileID          string   `json:"file_id"`
	AllFileIDs      []string `json:"all_file_ids,omitempty"`
	LogicalKey      string   `json:"logical_key"`
	DisplayPath     string   `json:"display_path"`
	Tenant          string   `json:"tenant,omitempty"`
	Verdict         string   `json:"verdict"`
	ReasonCode      string   `json:"reason_code,omitempty"`
	WitnessRecords  []string `json:"witness_records,omitempty"`
	BlockingRecords []string `json:"blocking_records,omitempty"`
}

// Link is one verifiable step of a reference chain.
type Link struct {
	Kind    string `json:"kind"`
	Detail  string `json:"detail,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	AliasID string `json:"alias_id,omitempty"`
	WM      int    `json:"wm,omitempty"`
}

// Chain is one record-to-file evidence path (or a broken attempt).
type Chain struct {
	ChainID       string `json:"chain_id"`
	RecordID      string `json:"record_id"`
	FileID        string `json:"file_id,omitempty"`
	Status        string `json:"status"`
	ReasonCode    string `json:"reason_code,omitempty"`
	ReasonMessage string `json:"reason_message,omitempty"`
	SourceSandbox string `json:"source_sandbox"`
	SourceTenant  string `json:"source_tenant,omitempty"`
	MatchKind     string `json:"match_kind,omitempty"`
	Links         []Link `json:"links"`
}

// RecordResult is the per-input-record rollup.
type RecordResult struct {
	RecordID       string   `json:"record_id"`
	Status         string   `json:"status"`
	ReasonCode     string   `json:"reason_code,omitempty"`
	ReasonMessage  string   `json:"reason_message,omitempty"`
	ChainIDs       []string `json:"chain_ids"`
	MatchedFileIDs []string `json:"matched_file_ids,omitempty"`
}

// BoundaryViolation records a denied directory/tenant boundary crossing.
type BoundaryViolation struct {
	RecordID string `json:"record_id"`
	FileID   string `json:"file_id,omitempty"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
}
