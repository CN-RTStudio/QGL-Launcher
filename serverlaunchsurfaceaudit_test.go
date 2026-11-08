package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func surfaceDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func writeSurfaceFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
		t.Fatalf("写入文件失败: %v", err)
	}
}

func TestAuditServerSurfaceClean(t *testing.T) {
	dir := surfaceDir(t)
	writeSurfaceFile(t, dir, "1.20.1-server.jar")
	writeSurfaceFile(t, dir, "eula.txt")
	if err := os.Mkdir(filepath.Join(dir, "plugins"), 0o700); err != nil {
		t.Fatalf("创建插件目录失败: %v", err)
	}
	audit, err := AuditServerSurface(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if len(audit.Findings) != 0 || audit.Blocking() {
		t.Fatalf("干净目录不应有问题: %v", audit.Describe())
	}
}

func TestAuditServerSurfaceExecutable(t *testing.T) {
	dir := surfaceDir(t)
	writeSurfaceFile(t, dir, "start.bat")
	audit, err := AuditServerSurface(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("根层批处理应阻断: %v", audit.Describe())
	}
	if got := audit.Findings[0].Reason; got != surfaceReasonExecutable {
		t.Fatalf("原因应为可执行文件，实际 %s", got)
	}
}

func TestAuditServerSurfacePowerShell(t *testing.T) {
	dir := surfaceDir(t)
	writeSurfaceFile(t, dir, "update.ps1")
	audit, err := AuditServerSurface(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("PowerShell 脚本应阻断: %v", audit.Describe())
	}
}

func TestAuditServerSurfaceExtraJar(t *testing.T) {
	dir := surfaceDir(t)
	writeSurfaceFile(t, dir, "client.jar")
	audit, err := AuditServerSurface(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() {
		t.Fatalf("额外 jar 只应告警: %v", audit.Describe())
	}
	if got := audit.Findings[0].Reason; got != surfaceReasonExtraJar {
		t.Fatalf("原因应为额外 jar，实际 %s", got)
	}
}

func TestAuditServerSurfaceSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 创建符号链接需要额外权限")
	}
	dir := surfaceDir(t)
	outside := filepath.Join(t.TempDir(), "dropper.exe")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入外部文件失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "run.exe")); err != nil {
		t.Skipf("创建符号链接失败: %v", err)
	}
	audit, err := AuditServerSurface(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("符号链接应阻断: %v", audit.Describe())
	}
	if got := audit.Findings[0].Reason; got != surfaceReasonSymlink {
		t.Fatalf("原因应为符号链接，实际 %s", got)
	}
}

func TestAuditServerSurfaceControlName(t *testing.T) {
	dir := surfaceDir(t)
	if err := os.WriteFile(filepath.Join(dir, "bad\x01name.txt"), []byte("x"), 0o600); err != nil {
		t.Skipf("文件系统拒绝控制字符名: %v", err)
	}
	audit, err := AuditServerSurface(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), surfaceReasonBadName) {
		t.Fatalf("控制字符文件名应阻断: %v", audit.Describe())
	}
}

func TestAuditServerSurfaceMissingDir(t *testing.T) {
	audit, err := AuditServerSurface(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("目录不存在时不应报告风险")
	}
}
