package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeLIB(t *testing.T, dir, rel string, body []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
}

func jarBody(size int) []byte {
	body := make([]byte, size)
	copy(body, []byte("PK\x03\x04"))
	return body
}

func TestAuditServerLibrariesMissing(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerLibraries(dir)
	if audit.Blocking() {
		t.Fatalf("missing libs is informational: %+v", audit.Findings)
	}
	if len(audit.Jars) != 0 {
		t.Fatalf("unexpected jars: %v", audit.Jars)
	}
	if len(audit.Findings) != 2 {
		t.Fatalf("expected missing+ok: %+v", audit.Findings)
	}
}

func TestAuditServerLibrariesClean(t *testing.T) {
	dir := t.TempDir()
	writeLIB(t, dir, filepath.Join("libs", "guava-31.1-jre.jar"), jarBody(2048), 0o644)
	writeLIB(t, dir, filepath.Join("libs", "asm-9.5.jar"), jarBody(1024), 0o644)
	audit := AuditServerLibraries(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("clean libs should pass: %+v", audit.Findings)
	}
	if len(audit.Jars) != 2 {
		t.Fatalf("expected two jars: %v", audit.Jars)
	}
	if audit.Describe() == "" || audit.Summary() == "" {
		t.Fatalf("describe/summary empty")
	}
}

func TestAuditServerLibrariesNotAJar(t *testing.T) {
	dir := t.TempDir()
	writeLIB(t, dir, filepath.Join("libs", "fake.jar"), []byte("plain text"), 0o644)
	audit := AuditServerLibraries(dir)
	if audit.Blocking() {
		t.Fatalf("bad header is a warning: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != libReasonNotAJar {
		t.Fatalf("expected not-a-jar: %+v", audit.Findings)
	}
}

func TestAuditServerLibrariesDuplicateVersion(t *testing.T) {
	dir := t.TempDir()
	writeLIB(t, dir, filepath.Join("libs", "guava-30.1.jar"), jarBody(1024), 0o644)
	writeLIB(t, dir, filepath.Join("libs", "guava-31.1.jar"), jarBody(1024), 0o644)
	audit := AuditServerLibraries(dir)
	if audit.Findings[0].Reason != libReasonDuplicateVersion {
		t.Fatalf("expected duplicate-version: %+v", audit.Findings)
	}
	if audit.Findings[0].Blocking {
		t.Fatalf("duplicate version is a warning")
	}
}

func TestAuditServerLibrariesShadowCopy(t *testing.T) {
	dir := t.TempDir()
	writeLIB(t, dir, filepath.Join("libs", "plugin.jar.old"), jarBody(1024), 0o644)
	writeLIB(t, dir, filepath.Join("libs", "plugin-1.0.jar"), jarBody(1024), 0o644)
	audit := AuditServerLibraries(dir)
	if audit.Findings[0].Reason != libReasonShadowCopy {
		t.Fatalf("expected shadow-copy: %+v", audit.Findings)
	}
}

func TestAuditServerLibrariesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.jar")
	if err := os.WriteFile(target, jarBody(1024), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "libs"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "libs", "link.jar")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	audit := AuditServerLibraries(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != libReasonSymlink {
		t.Fatalf("expected symlink block: %+v", audit.Findings)
	}
}

func TestAuditServerLibrariesWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("unix permission bits not meaningful on windows")
	}
	dir := t.TempDir()
	writeLIB(t, dir, filepath.Join("libs", "open.jar"), jarBody(1024), 0o666)
	audit := AuditServerLibraries(dir)
	if audit.Findings[0].Reason != libReasonWorldWritable {
		t.Fatalf("expected world-writable: %+v", audit.Findings)
	}
}

func TestAuditServerLibrariesNested(t *testing.T) {
	dir := t.TempDir()
	writeLIB(t, dir, filepath.Join("libraries", "com", "example", "lib", "1.0", "lib-1.0.jar"), jarBody(1024), 0o644)
	audit := AuditServerLibraries(dir)
	if len(audit.Jars) != 1 {
		t.Fatalf("nested jar should be found: %v", audit.Jars)
	}
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("nested jar should be clean: %+v", audit.Findings)
	}
}

func TestAuditServerLibrariesBadName(t *testing.T) {
	dir := t.TempDir()
	writeLIB(t, dir, filepath.Join("libs", "bad\x02.jar"), jarBody(1024), 0o644)
	audit := AuditServerLibraries(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != libReasonBadName {
		t.Fatalf("expected bad-name: %+v", audit.Findings)
	}
}

func TestAuditServerLibrariesDepthBudget(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "libs", "a", "b", "c", "d", "e", "f", "g", "h")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	audit := AuditServerLibraries(dir)
	found := false
	for _, f := range audit.Findings {
		if f.Reason == libReasonTooMany {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected depth budget finding: %+v", audit.Findings)
	}
}
