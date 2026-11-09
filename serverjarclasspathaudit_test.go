package main

import (
	"archive/zip"
	"os"
	"path/filepath"
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
