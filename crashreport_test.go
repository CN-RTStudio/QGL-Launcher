package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyCrashName(t *testing.T) {
	good := []struct{ in, kind string }{
		{"crash-2024-01-01_12.00.00-client.txt", "crash-report"},
		{"hs_err_pid12345.log", "hs-err"},
	}
	for _, c := range good {
		kind, ok := classifyCrashName(c.in)
		if !ok || kind != c.kind {
			t.Fatalf("%q: got %q ok=%v", c.in, kind, ok)
		}
	}
	for _, bad := range []string{"", "../evil.txt", "crash-1.txt/../x", "note.txt", "hs_err_pid1.txt", "x\x01y.txt"} {
		if _, ok := classifyCrashName(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestScanCrashSensitive(t *testing.T) {
	content := strings.Join([]string{
		"clean line",
		`"accessToken":"0123456789abcdef0123456789abcdef"`,
		"email steve@example.com logged",
		"uuid=01234567-89ab-cdef-0123-456789abcdef",
	}, "\n")
	lim := defaultCrashLimits()
	f, err := os.CreateTemp("", "crash*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	hits := scanCrashSensitive(mustOpen(f.Name()), 0, lim.MaxScanLines)
	if len(hits) != 3 {
		t.Fatalf("hits=%v want 3", hits)
	}
}

func mustOpen(p string) *os.File {
	f, err := os.Open(p)
	if err != nil {
		panic(err)
	}
	return f
}

func TestScanCrashDir(t *testing.T) {
	lim := defaultCrashLimits()
	root := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("crash-2024-01-01_10.00.00-client.txt", "plain report body")
	write("hs_err_pid99.log", "JVM crash log")
	write("crash-2024-01-01_11.00.00-client.txt", `"accessToken":"abcdef0123456789abcdef0123456789"`)

	vd := ScanCrashDir(root, lim)
	if vd.OK {
		t.Fatalf("expected sensitive hit")
	}
	if vd.Count != 3 {
		t.Fatalf("count=%d want 3", vd.Count)
	}
	if !strings.Contains(vd.Reason, "report-sensitive") {
		t.Fatalf("reason=%q", vd.Reason)
	}
}

func TestSummarizeCrashVerdict(t *testing.T) {
	if s := SummarizeCrashVerdict(crashVerdict{OK: true, Count: 2}); s != "crashreports ok count=2" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeCrashVerdict(crashVerdict{OK: false, Reason: "report-too-large:x"}); s != "crashreports bad report-too-large:x" {
		t.Fatalf("summary wrong: %q", s)
	}
}
