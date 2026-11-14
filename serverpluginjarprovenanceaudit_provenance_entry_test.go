package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
		"plugin.yml":           "name: Demo\nmain: a.b\n",
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nName: x\nSHA1-Digest: abc\n",
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
