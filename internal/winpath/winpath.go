// Package winpath performs strictly logical canonicalization of Windows-style
// paths found in synthetic audit records.
//
// It NEVER touches the real filesystem: no filepath.Abs, no working-directory
// lookup, no reparse-point evaluation. Drive-relative paths ("C:foo") cannot be
// canonicalized offline and are rejected instead of guessed.
//
// Canonicalization rules (documented in SOLUTION.md):
//   - leading/trailing Unicode whitespace padding is removed;
//   - '/' and '\' are equivalent and runs of separators collapse;
//   - the drive letter is upper-cased for Display; the identity Key is the
//     full lower-cased canonical path (Windows names are case-insensitive);
//   - "." and ".." are resolved lexically (leading ".." at the root drops);
//   - internal spaces are significant and preserved exactly;
//   - segment-prefix helpers are boundary aware ("a\b" never prefixes "a\b2").
package winpath

import (
	"errors"
	"strings"
)

// Key is the canonical identity of a logical path. It is always lower-cased.
type Key string

// Path holds both the identity key and a display-friendly canonical form.
type Path struct {
	Raw      string   `json:"raw"`
	Key      Key      `json:"key"`
	Display  string   `json:"display"`
	Segments []string `json:"segments"`
	IsUNC    bool     `json:"is_unc"`
}

// Errors returned for paths that cannot be canonicalized offline.
var (
	ErrEmpty        = errors.New("empty path after trimming whitespace")
	ErrRelative     = errors.New("relative path cannot be canonicalized offline")
	ErrDriveRel     = errors.New("drive-relative path (missing separator after drive) cannot be canonicalized offline")
	ErrUNCMalformed = errors.New("UNC path requires \\\\server\\share")
)

// Normalize canonicalizes a raw logical Windows path.
func Normalize(raw string) (Path, error) {
	p := Path{Raw: raw}

	s := strings.TrimSpace(raw)
	if s == "" {
		return p, ErrEmpty
	}
	s = strings.ReplaceAll(s, "/", `\`)

	isUNC := strings.HasPrefix(s, `\\`)
	p.IsUNC = isUNC

	// Split on separator runs; FieldsFunc drops empty tokens produced by
	// duplicated separators. Spaces are NOT treated as separators.
	rawParts := strings.FieldsFunc(s, func(r rune) bool { return r == '\\' })
	if len(rawParts) == 0 {
		return p, ErrEmpty
	}

	// keep is the number of leading segments inside `segs` that ".." may not
	// pop: 2 for UNC (server/share), 0 for drive paths (volume is separate).
	keep := 0
	vol := ""
	skipFirst := false

	switch {
	case isUNC:
		if len(rawParts) < 2 { // need \\server\share
			return p, ErrUNCMalformed
		}
		keep = 2
	case len(s) >= 2 && isASCIILetter(s[0]) && s[1] == ':':
		// Absolute requires a separator right after the colon. We test the
		// trimmed/replaced string, not rawParts, because "C:foo" merges.
		if len(s) < 3 || s[2] != '\\' {
			return p, ErrDriveRel
		}
		if len(rawParts) < 1 || !isDriveToken(rawParts[0]) {
			return p, ErrDriveRel
		}
		vol = strings.ToUpper(rawParts[0]) // "c:" -> "C:"
		skipFirst = true
	default:
		return p, ErrRelative
	}

	// Lexical "." / ".." resolution.
	segs := make([]string, 0, len(rawParts))
	for i, part := range rawParts {
		if skipFirst && i == 0 {
			continue // drive token is represented by vol
		}
		switch part {
		case "", ".":
			continue
		case "..":
			if len(segs) > keep {
				segs = segs[:len(segs)-1]
			}
			// At/above the protected root the segment is dropped.
		default:
			segs = append(segs, part)
		}
	}

	var display string
	if isUNC {
		display = `\\` + strings.Join(segs, `\`)
	} else if len(segs) == 0 {
		display = vol + `\`
	} else {
		display = vol + `\` + strings.Join(segs, `\`)
	}

	p.Display = display
	p.Key = Key(strings.ToLower(display))
	p.Segments = keySegments(p.Key)
	return p, nil
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isDriveToken(tok string) bool {
	return len(tok) == 2 && tok[1] == ':' && isASCIILetter(tok[0])
}

// MustKey normalizes or panics. Intended for package-level constants/tests of
// paths known to be valid; input data must use Normalize and handle errors.
func MustKey(raw string) Key {
	p, err := Normalize(raw)
	if err != nil {
		panic(err)
	}
	return p.Key
}

// Segments returns the lower-cased identity segments, dropping empty tokens.
// "c:\a\b" -> ["c:","a","b"]; `\\s\share\a` -> ["s","share","a"].
func (k Key) Segments() []string {
	return keySegments(k)
}

func keySegments(k Key) []string {
	return strings.FieldsFunc(string(k), func(r rune) bool { return r == '\\' })
}

// PrefixKeys returns every segment prefix of k, shortest first.
// For "c:\a\b" it returns "c:\", "c:\a", "c:\a\b".
func PrefixKeys(k Key) []Key {
	segs := k.Segments()
	out := make([]Key, 0, len(segs))
	for n := 1; n <= len(segs); n++ {
		out = append(out, keyFromSegments(segs[:n]))
	}
	return out
}

func keyFromSegments(segs []string) Key {
	if len(segs) == 0 {
		return ""
	}
	if strings.HasSuffix(segs[0], ":") {
		if len(segs) == 1 {
			return Key(segs[0] + `\`) // volume root "c:\"
		}
		return Key(segs[0] + `\` + strings.Join(segs[1:], `\`))
	}
	// UNC segment lists always start server,share and are reconstructed with \\.
	return Key(`\\` + strings.Join(segs, `\`))
}

// HasSegmentPrefix reports whether path equals prefix or lies strictly below
// it at a segment boundary. "c:\a\b2" does NOT have prefix "c:\a\b".
func HasSegmentPrefix(path, prefix Key) bool {
	_, ok := StripPrefix(path, prefix)
	return ok
}

// StripPrefix returns the segments below prefix when path is prefix-or-equal.
// ok is false when prefix is not a segment prefix.
func StripPrefix(path, prefix Key) ([]string, bool) {
	ps := prefix.Segments()
	qs := path.Segments()
	if len(ps) == 0 || len(qs) < len(ps) {
		return nil, false
	}
	for i := range ps {
		if qs[i] != ps[i] {
			return nil, false
		}
	}
	return qs[len(ps):], true
}

// ApplyPrefix joins a canonical target prefix with remaining suffix segments,
// preserving the target's volume/UNC shape.
func ApplyPrefix(target Key, rest []string) Key {
	base := strings.TrimSuffix(string(target), `\`)
	if len(rest) == 0 {
		if strings.HasSuffix(base, ":") {
			return Key(base + `\`) // preserve drive root
		}
		return Key(base)
	}
	if strings.HasSuffix(base, ":") {
		return Key(base + `\` + strings.Join(rest, `\`))
	}
	return Key(base + `\` + strings.Join(rest, `\`))
}
