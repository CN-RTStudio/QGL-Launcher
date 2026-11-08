package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJarCP(t *testing.T, dir, name, manifest string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	if manifest != "" {
		w, err := zw.Create(jarCpManifestPath)
		if err != nil {
			t.Fatalf("zip entry: %v", err)
		}
		if _, err := w.Write([]byte(manifest)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}

func jarHasReason(audit JarClassPathAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJarCleanRelativeClassPath(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "plugin.jar", "Manifest-Version: 1.0\r\nClass-Path: libs/a.jar libs/b.jar\r\n\r\n")
	audit := AuditServerJarClassPath(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("clean classpath should pass: %s", audit.Describe())
	}
	if audit.Jars != 1 {
		t.Fatalf("expected 1 jar, got %d", audit.Jars)
	}
}

func TestJarMissingDirectory(t *testing.T) {
	audit := AuditServerJarClassPath(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() || !jarHasReason(audit, jarCpReasonMissing) {
		t.Fatalf("missing dir must block: %s", audit.Describe())
	}
}

func TestJarAbsoluteClassPath(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "bad.jar", "Manifest-Version: 1.0\nClass-Path: /etc/passwd\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonAbsolute) || !audit.Blocking() {
		t.Fatalf("absolute classpath must block: %s", audit.Describe())
	}
}

func TestJarWindowsAbsoluteClassPath(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "bad.jar", "Manifest-Version: 1.0\nClass-Path: C:\\Windows\\System32\\secret.jar\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonAbsolute) {
		t.Fatalf("drive letter classpath not flagged: %s", audit.Describe())
	}
}

func TestJarTraversalClassPath(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "bad.jar", "Manifest-Version: 1.0\nClass-Path: ../../shared/evil.jar\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonTraversal) || !audit.Blocking() {
		t.Fatalf("traversal classpath must block: %s", audit.Describe())
	}
}

func TestJarRemoteClassPath(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "bad.jar", "Manifest-Version: 1.0\nClass-Path: https://evil.example/x.jar\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonRemote) {
		t.Fatalf("remote classpath not flagged: %s", audit.Describe())
	}
}

func TestJarFileSchemeClassPath(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "bad.jar", "Manifest-Version: 1.0\nClass-Path: file:///etc/x.jar\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonRemote) {
		t.Fatalf("file scheme not flagged: %s", audit.Describe())
	}
}

func TestJarManifestContinuationLines(t *testing.T) {
	dir := t.TempDir()
	manifest := "Manifest-Version: 1.0\nClass-Path: libs/a.jar\n ../../evil.jar\n"
	writeJarCP(t, filepath.Join(dir, "plugins"), "cont.jar", manifest)
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonTraversal) {
		t.Fatalf("continuation line not unfolded: %s", audit.Describe())
	}
}

func TestJarDuplicateClassPathEntry(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "dup.jar", "Manifest-Version: 1.0\nClass-Path: libs/a.jar libs/a.jar\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonDuplicate) {
		t.Fatalf("duplicate entry not flagged: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatal("duplicate entry should stay a warning")
	}
}

func TestJarAgentEntryWarning(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, filepath.Join(dir, "plugins"), "agent.jar", "Manifest-Version: 1.0\nPremain-Class: com.example.Premain\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonAgentEntry) {
		t.Fatalf("agent entry not flagged: %s", audit.Describe())
	}
}

func TestJarMissingManifest(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "plain.bin"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	writeJarCP(t, filepath.Join(dir, "plugins"), "bare.jar", "")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonNoManifest) {
		t.Fatalf("manifest missing not flagged: %s", audit.Describe())
	}
}

func TestJarNotAZip(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "plugins", "broken.jar")
	if err := os.WriteFile(path, []byte("not a zip at all"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonNotZip) || !audit.Blocking() {
		t.Fatalf("broken jar must block: %s", audit.Describe())
	}
}

func TestJarSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.jar")
	writeJarCP(t, dir, "outside.jar", "Manifest-Version: 1.0\n")
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, "plugins", "link.jar")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonUnreadable) || !audit.Blocking() {
		t.Fatalf("symlinked jar must block: %s", audit.Describe())
	}
}

func TestJarTooManyEntries(t *testing.T) {
	dir := t.TempDir()
	entries := []string{}
	for i := 0; i < jarCpMaxEntries+2; i++ {
		entries = append(entries, "libs/"+strings.Repeat("x", 3)+string(rune('a'+i%26))+".jar")
	}
	writeJarCP(t, filepath.Join(dir, "plugins"), "many.jar", "Manifest-Version: 1.0\nClass-Path: "+strings.Join(entries, " ")+"\n")
	audit := AuditServerJarClassPath(dir)
	if !jarHasReason(audit, jarCpReasonTooMany) {
		t.Fatalf("entry budget not enforced: %s", audit.Describe())
	}
}

func TestJarSummaryAndCodes(t *testing.T) {
	audit := JarClassPathAudit{Dir: "x"}
	audit.add("a.jar", "/x.jar", jarCpReasonAbsolute, "abs", true)
	audit.add("a.jar", "dup", jarCpReasonDuplicate, "dup", false)
	if codes := audit.Codes(); len(codes) != 2 || codes[0] != jarCpReasonAbsolute {
		t.Fatalf("codes wrong: %v", codes)
	}
	if !strings.Contains(audit.Summary(), "blocking=1") {
		t.Fatalf("summary wrong: %s", audit.Summary())
	}
	if !strings.Contains(audit.Describe(), "a.jar") {
		t.Fatalf("describe wrong: %s", audit.Describe())
	}
}

func TestJarRootScan(t *testing.T) {
	dir := t.TempDir()
	writeJarCP(t, dir, "server.jar", "Manifest-Version: 1.0\nClass-Path: libs/a.jar\n")
	audit := AuditServerJarClassPath(dir)
	if audit.Jars != 1 || audit.Blocking() {
		t.Fatalf("root jar scan failed: %s", audit.Describe())
	}
}
