package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bdHas(a BudgetAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func bdMakeDirs(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
}

func TestAuditServerBudgetHealthy(t *testing.T) {
	dir := t.TempDir()
	bdMakeDirs(t, dir, "world/region", "logs", "mods")
	if err := os.WriteFile(filepath.Join(dir, "world/region/r.0.0.mca"), make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "logs/latest.log"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mods/a.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	audit := AuditServerBudget(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("健康目录被误报: %s", audit.Describe())
	}
	if audit.Totals["world"] <= 0 {
		t.Fatalf("世界体积统计缺失: %v", audit.Totals)
	}
}

func TestAuditServerBudgetMissingDir(t *testing.T) {
	audit := AuditServerBudget(filepath.Join(t.TempDir(), "nope"))
	if audit.Blocking() {
		t.Fatalf("缺失目录不应阻断: %s", audit.Describe())
	}
	if !bdHas(audit, bdReasonMissing) {
		t.Fatalf("缺少 missing: %s", audit.Describe())
	}
}

func TestAuditServerBudgetWorldSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(t.TempDir(), "shared-world")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "world")); err != nil {
		t.Skip("平台不支持符号链接")
	}
	audit := AuditServerBudget(dir)
	if !audit.Blocking() || !bdHas(audit, bdReasonWorldSymlink) {
		t.Fatalf("世界目录符号链接未阻断: %s", audit.Describe())
	}
}

func TestAuditServerBudgetWorldInnerSymlink(t *testing.T) {
	dir := t.TempDir()
	bdMakeDirs(t, dir, "world/region")
	if err := os.Symlink("/etc/hosts", filepath.Join(dir, "world/region/link.mca")); err != nil {
		t.Skip("平台不支持符号链接")
	}
	audit := AuditServerBudget(dir)
	if !bdHas(audit, bdReasonWorldSymlink) {
		t.Fatalf("世界内符号链接未检出: %s", audit.Describe())
	}
}

func TestAuditServerBudgetLargeLogs(t *testing.T) {
	dir := t.TempDir()
	bdMakeDirs(t, dir, "logs")
	path := filepath.Join(dir, "logs", "big.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(bdMaxLogBytes + 1024); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()
	audit := AuditServerBudget(dir)
	if !bdHas(audit, bdReasonLogLarge) {
		t.Fatalf("超大日志未检出: %s", audit.Describe())
	}
}

func TestAuditServerBudgetCrashReports(t *testing.T) {
	dir := t.TempDir()
	bdMakeDirs(t, dir, "crash-reports")
	for i := 0; i < bdMaxCrashReports+2; i++ {
		name := filepath.Join(dir, "crash-reports", fmt.Sprintf("crash-2026-%03d.txt", i))
		if err := os.WriteFile(name, []byte("boom"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	audit := AuditServerBudget(dir)
	if !bdHas(audit, bdReasonCrashMany) {
		t.Fatalf("崩溃报告数量未检出: %s", audit.Describe())
	}
}

func TestAuditServerBudgetTooManyMods(t *testing.T) {
	dir := t.TempDir()
	bdMakeDirs(t, dir, "mods")
	for i := 0; i < bdMaxMods+3; i++ {
		name := filepath.Join(dir, "mods", fmt.Sprintf("mod-%03d.jar", i))
		if err := os.WriteFile(name, []byte("jar"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	audit := AuditServerBudget(dir)
	if !bdHas(audit, bdReasonModsMany) {
		t.Fatalf("模组数量未检出: %s", audit.Describe())
	}
}

func TestAuditServerBudgetDatapacks(t *testing.T) {
	dir := t.TempDir()
	bdMakeDirs(t, dir, "datapacks")
	for i := 0; i < bdMaxDatapacks+2; i++ {
		name := filepath.Join(dir, "datapacks", fmt.Sprintf("pack-%03d.zip", i))
		if err := os.WriteFile(name, []byte("zip"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	audit := AuditServerBudget(dir)
	if !bdHas(audit, bdReasonDatapacksMany) {
		t.Fatalf("数据包数量未检出: %s", audit.Describe())
	}
}

func TestbdHuman(t *testing.T) {
	cases := map[int64]string{
		512:     "512B",
		1024:    "1.0KB",
		1536:    "1.5KB",
		1 << 20: "1.0MB",
		1 << 30: "1.0GB",
	}
	for bytes, want := range cases {
		if got := bdHuman(bytes); got != want {
			t.Fatalf("bdHuman(%d)=%s want %s", bytes, got, want)
		}
	}
}

func TestbdCountDirEntriesFilter(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.jar"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	count := bdCountDirEntries(dir, 10, func(name string) bool {
		return strings.HasSuffix(name, ".jar")
	})
	if count != 1 {
		t.Fatalf("过滤计数错误: %d", count)
	}
}

func TestAuditServerBudgetDescribe(t *testing.T) {
	dir := t.TempDir()
	bdMakeDirs(t, dir, "logs")
	path := filepath.Join(dir, "logs", "big.log")
	f, _ := os.Create(path)
	_ = f.Truncate(bdMaxLogBytes + 1)
	f.Close()
	audit := AuditServerBudget(dir)
	if !strings.Contains(audit.Describe(), bdReasonLogLarge) {
		t.Fatalf("描述缺少原因: %s", audit.Describe())
	}
}
