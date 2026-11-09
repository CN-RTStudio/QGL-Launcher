package main

import (
	"os"
	"path/filepath"
	"testing"
)

func skWrite(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func skHas(a StartupSecretAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestStartupSecretClean(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "start.sh", "#!/bin/sh\njava -Xmx4G -jar server.jar nogui\n", 0o700)
	a := AuditServerStartupSecrets(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("期望无风险，得到 %s", a.Describe())
	}
}

func TestStartupSecretPlainPassword(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "start.sh", "#!/bin/sh\nrcon.password=supersecret123\n", 0o600)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonPlainSecret) || !a.Blocking() {
		t.Fatalf("期望 plaintext-secret 阻断，得到 %s", a.Describe())
	}
}

func TestStartupSecretPropertySecret(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "user_jvm_args.txt", "-Ddb.password=hunter2 -Xmx2G\n", 0o600)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonPropSecret) && !skHas(a, skReasonPlainSecret) {
		t.Fatalf("期望系统属性口令阻断，得到 %s", a.Describe())
	}
}

func TestStartupSecretURLCreds(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "run.sh", "curl -s https://user:pass123@example.invalid/manifest.json\n", 0o600)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonURLCreds) {
		t.Fatalf("期望 url-credentials，得到 %s", a.Describe())
	}
}

func TestStartupSecretTokenArg(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "start.bat", "java -jar launcher.jar --accessToken abcdef123\n", 0o600)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonTokenArg) {
		t.Fatalf("期望 token-argument，得到 %s", a.Describe())
	}
}

func TestStartupSecretRCONArg(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "run.sh", "rcon-cli -p letmein123 \"list\"\n", 0o600)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonRCONArg) {
	t.Fatalf("期望 rcon-password-argument，得到 %s", a.Describe())
	}
}

func TestStartupSecretEnvSecret(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "start.sh", "export RCON_PASSWORD=letmein123\n", 0o600)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonEnvSecret) {
		t.Fatalf("期望 env-secret，得到 %s", a.Describe())
	}
}

func TestStartupSecretSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "start.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "start.sh")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestStartupSecretWorldWritable(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "start.sh", "#!/bin/sh\njava -jar server.jar\n", 0o666)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonWorldWritable) || !a.Blocking() {
		t.Fatalf("期望 world-writable 阻断，得到 %s", a.Describe())
	}
}

func TestStartupSecretWorldReadableSecret(t *testing.T) {
	dir := t.TempDir()
	skWrite(t, dir, "start.sh", "#!/bin/sh\nrcon.password=letmein123\n", 0o644)
	a := AuditServerStartupSecrets(dir)
	if !skHas(a, skReasonWorldReadable) {
		t.Fatalf("期望 world-readable 告警，得到 %s", a.Describe())
	}
}

func TestStartupSecretMissingDir(t *testing.T) {
	a := AuditServerStartupSecrets(filepath.Join(t.TempDir(), "absent"))
	if !a.Blocking() {
		t.Fatalf("期望目录缺失阻断，得到 %s", a.Describe())
	}
}
