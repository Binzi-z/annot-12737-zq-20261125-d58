// Command audit runs the offline quarantine reference audit on a synthetic
// JSON case. It performs no filesystem operations against real directories.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"quaraudit/internal/engine"
	"quaraudit/internal/model"
	"quaraudit/internal/render"
)

func main() {
	casePath := flag.String("case", "testdata/truth/case_small.json", "path to synthetic case JSON")
	jsonOut := flag.String("json", "", "write machine-readable report JSON to this path")
	textOut := flag.String("text", "", "write plain-text report here ('-' means stdout)")
	flag.Parse()

	data, err := os.ReadFile(*casePath)
	if err != nil {
		fatal("read case: %v", err)
	}
	var c model.Case
	if err := json.Unmarshal(data, &c); err != nil {
		fatal("parse case JSON: %v", err)
	}

	rep, err := engine.Audit(&c)
	if err != nil {
		fatal("audit: %v", err)
	}

	if *jsonOut != "" {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fatal("marshal report: %v", err)
		}
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			fatal("write json: %v", err)
		}
	}

	text := render.Text(rep)
	switch {
	case *textOut == "-":
		fmt.Print(text)
	case *textOut != "":
		if err := os.WriteFile(*textOut, []byte(text), 0o644); err != nil {
			fatal("write text: %v", err)
		}
	case *jsonOut == "":
		fmt.Print(text)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "audit: "+format+"\n", args...)
	os.Exit(2)
}
