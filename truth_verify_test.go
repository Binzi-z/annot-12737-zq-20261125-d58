package quaraudit_test

// This test wires the real engine output to the INDEPENDENT verifier and checks
// the hand-authored truth set item by item. The verifier package itself does
// not import the engine; only this wiring test does.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"quaraudit/internal/engine"
	"quaraudit/internal/model"
	"quaraudit/internal/render"
	"quaraudit/internal/verify"
)

const (
	truthCasePath     = "testdata/truth/case_small.json"
	truthExpectedPath = "testdata/truth/expected_small.json"
)

func loadTruthReport(t *testing.T) ([]byte, *verify.Outcome) {
	t.Helper()

	cb, err := os.ReadFile(truthCasePath)
	if err != nil {
		t.Fatalf("read case: %v", err)
	}
	var c model.Case
	if err := json.Unmarshal(cb, &c); err != nil {
		t.Fatalf("parse case: %v", err)
	}
	rep, err := engine.Audit(&c)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	rb, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	tb, err := os.ReadFile(truthExpectedPath)
	if err != nil {
		t.Fatalf("read truth: %v", err)
	}
	out, err := verify.Check(rb, tb)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return append(rb, '\n'), out
}

func TestSmallTruthSetItemByItem(t *testing.T) {
	rb, out := loadTruthReport(t)

	for _, line := range out.FormatLines() {
		t.Log(line)
	}
	if !out.OK {
		t.Fatalf("independent verifier: %d/%d checks failed", out.Failed, out.Passed+out.Failed)
	}

	// Materialize the item-by-item verifier transcript as a genuine artifact.
	if err := os.MkdirAll("examples", 0o755); err == nil {
		transcript := "独立验证器逐条对照 (independent verifier vs hand-authored truth)\n" +
			"================================================================\n"
		for _, l := range out.FormatLines() {
			transcript += l + "\n"
		}
		_ = os.WriteFile(filepath.Join("examples", "verification_small.txt"), []byte(transcript), 0o644)
	}

	// Materialize the genuine generated example artifacts so cmd/verify can be
	// demonstrated out-of-process afterwards. Best effort: never fail the test
	// if the examples directory is not writable.
	if err := os.MkdirAll("examples", 0o755); err == nil {
		if err := os.WriteFile(filepath.Join("examples", "report_small.json"), rb, 0o644); err != nil {
			t.Logf("note: could not write example json: %v", err)
		}
		// Re-run audit to render text (cheap, deterministic).
		cb, _ := os.ReadFile(truthCasePath)
		var c model.Case
		if json.Unmarshal(cb, &c) == nil {
			if rep, err := engine.Audit(&c); err == nil {
				_ = os.WriteFile(filepath.Join("examples", "report_small.txt"),
					[]byte(render.Text(rep)), 0o644)
			}
		}
	}
}

// TestVerifierRejectsWrongTruth proves the checker actually has teeth: a
// deliberately wrong expectation must produce a failed outcome rather than a
// false pass.
func TestVerifierRejectsWrongTruth(t *testing.T) {
	rb, good := loadTruthReport(t)
	if !good.OK {
		t.Fatal("baseline truth must pass before testing rejection")
	}

	bad := []byte(`{
      "schema":"quaraudit.truth/v1",
      "case_id":"TRUTH-SMALL",
      "expect_files":[{"file_id":"F01","verdict":"FREE"}],
      "expect_records":[],
      "expect_summary":{"held": 999}
    }`)
	out, err := verify.Check(rb, bad)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if out.OK {
		t.Fatal("verifier accepted a deliberately wrong truth document")
	}
}
