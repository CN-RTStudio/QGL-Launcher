package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
