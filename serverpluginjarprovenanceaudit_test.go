package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pjWriteJar(t *testing.T, dir, name string, files map[string]string) {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create jar: %v", err)
	}
	writer := zip.NewWriter(f)
	for entry, body := range files {
		w, err := writer.Create(entry)
		if err != nil {
			t.Fatalf("create entry: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
}

func pjHasReason(audit PluginJarAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func pjServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}
	return dir
}

func TestPluginJarMissingDirectory(t *testing.T) {
	audit := AuditServerPluginJars(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() {
		t.Fatal("missing server directory must block")
	}
	if !pjHasReason(audit, pjReasonMissing) {
		t.Fatal("missing reason not reported")
	}
}

func TestPluginJarEmptyPluginsDir(t *testing.T) {
	audit := AuditServerPluginJars(pjServer(t))
	if audit.Blocking() {
		t.Fatalf("empty plugins must not block: %s", audit.Describe())
	}
	if !pjHasReason(audit, pjReasonEmpty) {
		t.Fatal("empty reason not reported")
	}
}

func TestPluginJarValidDescriptor(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "ok.jar", map[string]string{
		"plugin.yml":            "name: Demo\nmain: com.example.Demo\napi-version: 1.20\n",
		"META-INF/MANIFEST.MF":  "Manifest-Version: 1.0\n",
		"META-INF/MANIFEST.SF":  "Signature-Version: 1.0\n",
		"META-INF/MANIFEST.RSA": "sig\n",
	})
	audit := AuditServerPluginJars(dir)
	if audit.Blocking() {
		t.Fatalf("valid jar must not block: %s", audit.Describe())
	}
	if len(audit.Jars) != 1 {
		t.Fatalf("expected one jar, got %v", audit.Jars)
	}
}

func TestPluginJarMissingDescriptorBlocks(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "nope.jar", map[string]string{
		"com/example/Main.class": "x",
	})
	audit := AuditServerPluginJars(dir)
	if !audit.Blocking() {
		t.Fatal("jar without descriptor must block")
	}
	if !pjHasReason(audit, pjReasonNoDescriptor) {
		t.Fatal("missing descriptor reason not reported")
	}
}

func TestPluginJarMissingMainBlocks(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "nomain.jar", map[string]string{
		"plugin.yml": "name: Demo\nversion: 1.0\n",
	})
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonNoMain) {
		t.Fatal("missing main reason not reported")
	}
}

func TestPluginJarTraversalEntryBlocks(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "slip.jar", map[string]string{
		"plugin.yml":    "name: Demo\nmain: a.b\n",
		"../../evil.sh": "x",
	})
	audit := AuditServerPluginJars(dir)
	if !audit.Blocking() {
		t.Fatal("zip slip entry must block")
	}
	if !pjHasReason(audit, pjReasonBadName) {
		t.Fatal("bad name reason not reported")
	}
}
