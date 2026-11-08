package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sfaWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sfaHas(a *AdminFeedbackAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAdminFeedbackClean(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "op-permission-level=2\nfunction-permission-level=2\nenable-command-block=false\nlog-admin-commands=true\nbroadcast-console-to-ops=false\n")
	a := AuditServerAdminFeedback(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净配置不应阻断: %v", a.Describe())
	}
	if a.Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}

func TestAdminFeedbackMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestAdminFeedbackEmptyDir(t *testing.T) {
	a := AuditServerAdminFeedback("")
	if !sfaHas(a, sfaMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestAdminFeedbackOpLevelOutOfRange(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "op-permission-level=7\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaOpLevel) {
		t.Fatalf("越界档位应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("越界档位应阻断: %v", a.Describe())
	}
}

func TestAdminFeedbackOpLevelNotInteger(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "op-permission-level=high\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaOpLevel) {
		t.Fatalf("非整数档位应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非整数档位应阻断: %v", a.Describe())
	}
}

func TestAdminFeedbackOpLevelMaximumWarns(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "op-permission-level=4\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaOpLevelMax) {
		t.Fatalf("最高档位应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("最高档位不应阻断: %v", a.Describe())
	}
}

func TestAdminFeedbackFunctionLevelLow(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "function-permission-level=1\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaFuncLevel) {
		t.Fatalf("函数权限过低应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("函数权限过低应阻断: %v", a.Describe())
	}
}

func TestAdminFeedbackCommandBlockEnabled(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "enable-command-block=true\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaCommandBlk) {
		t.Fatalf("命令方块启用应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("命令方块启用应阻断: %v", a.Describe())
	}
}

func TestAdminFeedbackConsoleBroadcast(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "broadcast-console-to-ops=true\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaConsoleOPS) {
		t.Fatalf("控制台广播应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("控制台广播不应阻断: %v", a.Describe())
	}
}

func TestAdminFeedbackRconBroadcast(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "broadcast-rcon-to-ops=true\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaRconOPS) {
		t.Fatalf("RCON 广播应提示: %v", a.Describe())
	}
}

func TestAdminFeedbackAdminLogOff(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "log-admin-commands=false\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaAdminLog) {
		t.Fatalf("关闭管理员日志应提示: %v", a.Describe())
	}
}

func TestAdminFeedbackFeedbackOn(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "send-command-feedback=true\n")
	a := AuditServerAdminFeedback(dir)
	if !sfaHas(a, sfaFeedback) {
		t.Fatalf("命令反馈开启应提示: %v", a.Describe())
	}
}

func TestAdminFeedbackBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	sfaWrite(t, dir, "\ufeffop-permission-level=\"2\"\nlog-admin-commands=\"true\"\n")
	a := AuditServerAdminFeedback(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}
