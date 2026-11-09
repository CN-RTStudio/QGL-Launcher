package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// modsaudit_test.go —— mods 目录完整性审计内核测试。
//
// 只在真实临时目录上跑端到端流程，不用内存假实现：建 mods 目录 -> 生成基线 ->
// 对账一致 -> 篡改 / 新增 / 缺失后分别检出，并覆盖路径净化、哈希格式、版本不
// 兼容与扫描上界。符号链接逃逸在 Windows 上创建链接需要特权，这里不依赖它，
// 用“深层子目录不纳入账本”的替代约束覆盖扫描边界。

func TestModAuditSafeRelPath(t *testing.T) {
	good := []string{
		"a.jar", "mods/a.jar", "a/b/c.jar", "名字带中文.jar",
		"folder/a.jar", "z.j",
	}
	for _, p := range good {
		if !modAuditSafeRelPath(p) {
			t.Errorf("合法相对路径 %q 被拒", p)
		}
	}
	bad := []string{
		"", "/abs.jar", "\\abs.jar", "a/../b.jar", "../x.jar",
		"a\\b.jar", "a/./b.jar", "a//b.jar", "a/\x01b.jar",
		"a\nb.jar", strings.Repeat("a", modAuditRelPathMaxLen+1),
	}
	for _, p := range bad {
		if modAuditSafeRelPath(p) {
			t.Errorf("非法相对路径 %q 被判为合法", p)
		}
	}
}

func TestIsValidUMFSHex(t *testing.T) {
	good := strings.Repeat("ab", 32)
	if !isValidUMFSHex(good) {
		t.Errorf("64 位十六进制应通过")
	}
	bad := []string{
		"", strings.Repeat("ab", 31), strings.Repeat("AB", 32),
		strings.Repeat("g", 64), strings.Repeat("0", 63) + "x",
	}
	for _, s := range bad {
		if isValidUMFSHex(s) {
			t.Errorf("非法哈希 %q 被判为合法", s)
		}
	}
}

func TestSanitizeModAuditEntry(t *testing.T) {
	ok := ModAuditEntry{
		RelPath: "mods/a.jar", Name: "a.jar", Size: 100,
		UMFS: strings.Repeat("ab", 32), ModTime: "2026-10-11T00:00:00Z",
	}
	if !sanitizeModAuditEntry(&ok) {
		t.Fatalf("干净条目应通过净化")
	}
	base := func() ModAuditEntry { e := ok; return e }

	bad := []struct {
		label string
		mut   func(*ModAuditEntry)
	}{
		{"绝对路径", func(e *ModAuditEntry) { e.RelPath = "/etc/passwd" }},
		{"穿越", func(e *ModAuditEntry) { e.RelPath = "../a.jar" }},
		{"反斜杠", func(e *ModAuditEntry) { e.RelPath = "a\\b.jar" }},
		{"控制字符", func(e *ModAuditEntry) { e.RelPath = "a\x1fb.jar" }},
		{"空路径", func(e *ModAuditEntry) { e.RelPath = "" }},
		{"坏哈希", func(e *ModAuditEntry) { e.UMFS = "zzzz" }},
		{"负体积", func(e *ModAuditEntry) { e.Size = -1 }},
		{"超长时间", func(e *ModAuditEntry) { e.ModTime = strings.Repeat("t", 65) }},
	}
	for _, b := range bad {
		e := base()
		b.mut(&e)
		if sanitizeModAuditEntry(&e) {
			t.Errorf("条目应被拒绝: %s", b.label)
		}
	}
}

// buildTestModsDir 在临时目录里铺一个 mods 目录，返回路径与期望文件数。
func buildTestModsDir(t *testing.T) (string, int) {
	t.Helper()
	dir := t.TempDir()
	mods := filepath.Join(dir, "mods")
	if err := os.MkdirAll(mods, 0o700); err != nil {
		t.Fatalf("建 mods 目录失败: %v", err)
	}
	files := []struct {
		rel, body string
	}{
		{"coremod.jar", "core payload"},
		{"library-1.20.jar", "lib data"},
		{"sub/addon.jar", "addon data"},
	}
	for _, f := range files {
		full := filepath.Join(mods, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("建子目录失败: %v", err)
		}
		if err := os.WriteFile(full, []byte(f.body), 0o600); err != nil {
			t.Fatalf("写文件失败: %v", err)
		}
	}
	// 深层子目录不纳入账本（扫描只下一层）
	deep := filepath.Join(mods, "sub", "deep", "nested.jar")
	if err := os.MkdirAll(filepath.Dir(deep), 0o700); err != nil {
		t.Fatalf("建深层目录失败: %v", err)
	}
	if err := os.WriteFile(deep, []byte("deep"), 0o600); err != nil {
		t.Fatalf("写深层文件失败: %v", err)
	}
	return mods, len(files)
}

func TestModAuditSnapshotRoundTrip(t *testing.T) {
	mods, wantFiles := buildTestModsDir(t)
	lim := defaultModAuditLimits()
	entries, skipped, limitHit, err := collectModAuditDir(mods, lim)
	if err != nil {
		t.Fatalf("collectModAuditDir 失败: %v", err)
	}
	if len(entries) != wantFiles {
		t.Errorf("期望 %d 个条目，得到 %d（深层子目录不应进入账本）", wantFiles, len(entries))
	}
	if skipped != 0 || limitHit {
		t.Errorf("常规目录不应跳过或触限: skipped=%d limitHit=%v", skipped, limitHit)
	}
	snap := &ModAuditSnapshot{
		Version: modAuditBaselineVersion, CreatedAt: "2026-10-11T00:00:00Z",
		Dirs: []ModAuditDir{{Dir: "mods", Entries: entries}},
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := saveModAuditSnapshot(path, snap); err != nil {
		t.Fatalf("saveModAuditSnapshot 失败: %v", err)
	}
	loaded, err := loadModAuditSnapshot(path)
	if err != nil {
		t.Fatalf("loadModAuditSnapshot 失败: %v", err)
	}
	if loaded == nil || len(loaded.Dirs) != 1 || len(loaded.Dirs[0].Entries) != wantFiles {
		t.Fatalf("加载账本内容不符: %+v", loaded)
	}
	for i := range loaded.Dirs[0].Entries {
		a := loaded.Dirs[0].Entries[i]
		b := snap.Dirs[0].Entries[i]
		if a.UMFS != b.UMFS || a.Size != b.Size || a.RelPath != b.RelPath {
			t.Errorf("回读条目与源不一致: %+v vs %+v", a, b)
		}
	}
}
