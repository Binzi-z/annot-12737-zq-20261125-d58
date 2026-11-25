// Command verify is the independent truth-set checker. It compares an audit
// report JSON against a hand-authored truth JSON, item by item. It never
// imports the audit engine; it only reads the stable report wire format.
//
// Exit code 0 only when every expectation and structural invariant passes.
package main

import (
	"flag"
	"fmt"
	"os"

	"quaraudit/internal/verify"
)

func main() {
	reportPath := flag.String("report", "examples/report_small.json", "audit report JSON to check")
	truthPath := flag.String("truth", "testdata/truth/expected_small.json", "hand-authored truth JSON")
	flag.Parse()

	rb, err := os.ReadFile(*reportPath)
	if err != nil {
		fatal("read report: %v", err)
	}
	tb, err := os.ReadFile(*truthPath)
	if err != nil {
		fatal("read truth: %v", err)
	}

	out, err := verify.Check(rb, tb)
	if err != nil {
		fatal("%v", err)
	}
	for _, line := range out.FormatLines() {
		fmt.Println(line)
	}
	if !out.OK {
		os.Exit(1)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verify: "+format+"\n", args...)
	os.Exit(2)
}
