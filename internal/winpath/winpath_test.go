package winpath

import "testing"

func TestNormalizeEquivalentSpellings(t *testing.T) {
	variants := []string{
		`C:\Isolation\T100\files\f01.bin`,
		`c:\isolation\t100\files\f01.bin`,
		`C:\\Isolation\\T100\\files\\f01.bin`,
		`C:/Isolation/T100/files/f01.bin`,
		`C:\Isolation/./T100\files\sub\..\f01.bin`,
		`  C:\Isolation\T100\files\f01.bin  `,
		"\tC:\\Isolation\\T100\\files\\f01.bin\r\n",
	}
	want := MustKey(`c:\isolation\t100\files\f01.bin`)
	for i, v := range variants {
		got, err := Normalize(v)
		if err != nil {
			t.Fatalf("variant %d %q: unexpected error: %v", i, v, err)
		}
		if got.Key != want {
			t.Errorf("variant %d %q:\n got key %q\nwant     %q (display %q)", i, v, got.Key, want, got.Display)
		}
	}
}

func TestSpacesAreSignificantInside(t *testing.T) {
	a, err := Normalize(`C:\Q\sub dir\f 04.bin`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Normalize(`c:\q\sub dir\f 04.bin`)
	if err != nil {
		t.Fatal(err)
	}
	if a.Key != b.Key {
		t.Fatalf("case should fold: %q vs %q", a.Key, b.Key)
	}
	neighbor, err := Normalize(`C:\Q\subdir\f04.bin`)
	if err != nil {
		t.Fatal(err)
	}
	if a.Key == neighbor.Key {
		t.Fatal("internal space must not be stripped: paths collapsed incorrectly")
	}
}

func TestLexicalDotDot(t *testing.T) {
	cases := map[string]Key{
		`C:\a\b\..\c`:      MustKey(`c:\a\c`),
		`C:\a\..\..\x`:     MustKey(`c:\x`), // cannot escape volume root
		`C:\a\.\b`:         MustKey(`c:\a\b`),
		`\\s\share\a\..\b`: MustKey(`\\s\share\b`),
	}
	for raw, want := range cases {
		got, err := Normalize(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if got.Key != want {
			t.Errorf("%q -> %q, want %q", raw, got.Key, want)
		}
	}
}

func TestOfflineRejections(t *testing.T) {
	for _, raw := range []string{"", "   ", `relative\path`, `C:foo\bar`, `\no\drive`} {
		if _, err := Normalize(raw); err == nil {
			t.Errorf("expected error for %q", raw)
		}
	}
}

func TestSegmentPrefixBoundary(t *testing.T) {
	alias := MustKey(`c:\tenants\t0\mnt\green`)
	inside := MustKey(`C:\Tenants\T0\mnt\green\g1.dat`)
	trap1 := MustKey(`c:\tenants\t0\mnt\green2\g1.dat`)
	trap2 := MustKey(`c:\tenants\t0\mnt\green-backup\g1.dat`)

	if !HasSegmentPrefix(inside, alias) {
		t.Error("inside path must have alias prefix")
	}
	for _, trap := range []Key{trap1, trap2} {
		if HasSegmentPrefix(trap, alias) {
			t.Errorf("prefix leak across directory boundary: %q under %q", trap, alias)
		}
	}

	rest, ok := StripPrefix(inside, alias)
	if !ok || len(rest) != 1 || rest[0] != "g1.dat" {
		t.Errorf("StripPrefix = %v,%v", rest, ok)
	}

	rewritten := ApplyPrefix(MustKey(`d:\data\blue`), rest)
	if want := MustKey(`d:\data\blue\g1.dat`); rewritten != want {
		t.Errorf("rewrite = %q, want %q", rewritten, want)
	}
}

func TestPrefixKeys(t *testing.T) {
	got := PrefixKeys(MustKey(`c:\a\b`))
	want := []Key{Key("c:\\"), Key("c:\\a"), Key("c:\\a\\b")}
	if len(got) != len(want) {
		t.Fatalf("PrefixKeys len = %d (%v), want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix %d = %q, want %q", i, got[i], want[i])
		}
	}
}
