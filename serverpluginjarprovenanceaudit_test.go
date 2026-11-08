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
		"plugin.yml":              "name: Demo\nmain: com.example.Demo\napi-version: 1.20\n",
		"META-INF/MANIFEST.MF":    "Manifest-Version: 1.0\n",
		"META-INF/MANIFEST.SF":    "Signature-Version: 1.0\n",
		"META-INF/MANIFEST.RSA":   "sig\n",
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
		"plugin.yml":   "name: Demo\nmain: a.b\n",
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

func TestPluginJarBadMainClassBlocks(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "bad.jar", map[string]string{
		"plugin.yml": "name: Demo\nmain: ../com/example/Demo\n",
	})
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonBadMain) {
		t.Fatal("bad main reason not reported")
	}
}

func TestPluginJarShellMainWarns(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "shell.jar", map[string]string{
		"plugin.yml": "name: Demo\nmain: com.example.ShellRuntime.exec\n",
	})
	audit := AuditServerPluginJars(dir)
	if audit.Blocking() {
		t.Fatalf("shell main must not block: %s", audit.Describe())
	}
	if !pjHasReason(audit, pjReasonShellClass) {
		t.Fatal("shell main reason not reported")
	}
}

func TestPluginJarSymlinkBlocks(t *testing.T) {
	dir := pjServer(t)
	target := filepath.Join(dir, "outside.jar")
	pjWriteJar(t, dir, "outside.jar", map[string]string{
		"plugin.yml": "name: Demo\nmain: a.b\n",
	})
	if err := os.Symlink(target, filepath.Join(dir, "plugins", "link.jar")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonSymlink) {
		t.Fatal("symlink reason not reported")
	}
}

func TestPluginJarWeakManifestDigestBlocks(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "weak.jar", map[string]string{
		"plugin.yml":            "name: Demo\nmain: a.b\n",
		"META-INF/MANIFEST.MF":  "Manifest-Version: 1.0\nName: x\nSHA1-Digest: abc\n",
	})
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonWeakDigest) {
		t.Fatal("weak digest reason not reported")
	}
}

func TestPluginJarDuplicateWarns(t *testing.T) {
	dir := pjServer(t)
	for _, name := range []string{"demo.jar", "Demo.jar"} {
		pjWriteJar(t, filepath.Join(dir, "plugins"), name, map[string]string{
			"plugin.yml": "name: Demo\nmain: a.b\n",
		})
	}
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonDuplicateJar) {
		t.Fatal("duplicate jar not reported")
	}
}

func TestPluginJarBadFileNameWarns(t *testing.T) {
	dir := pjServer(t)
	pjWriteJar(t, filepath.Join(dir, "plugins"), "bad name.jar", map[string]string{
		"plugin.yml": "name: Demo\nmain: a.b\n",
	})
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonBadName) {
		t.Fatal("bad file name not reported")
	}
}

func TestPluginJarTooManyBlocks(t *testing.T) {
	dir := pjServer(t)
	for i := 0; i < pjMaxJars+4; i++ {
		pjWriteJar(t, filepath.Join(dir, "plugins"), "bulk"+itoaPJ(i)+".jar", map[string]string{
			"plugin.yml": "name: Demo\nmain: a.b\n",
		})
	}
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonTooMany) {
		t.Fatal("too many jars not reported")
	}
}

func itoaPJ(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestPluginJarEmptyFileBlocks(t *testing.T) {
	dir := pjServer(t)
	if err := os.WriteFile(filepath.Join(dir, "plugins", "zero.jar"), nil, 0o600); err != nil {
		t.Fatalf("write zero jar: %v", err)
	}
	audit := AuditServerPluginJars(dir)
	if !pjHasReason(audit, pjReasonEmpty) {
		t.Fatal("empty jar not reported")
	}
}

func TestPluginJarDescribeSkipsOK(t *testing.T) {
	audit := PluginJarAudit{}
	audit.add("", pjReasonOK, "fine", false)
	if audit.Describe() != "插件包结构未发现风险" {
		t.Fatalf("unexpected describe: %s", audit.Describe())
	}
}
