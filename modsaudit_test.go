package main

// modsaudit_test.go —— mods 目录完整性审计内核测试。
//
// 只在真实临时目录上跑端到端流程，不用内存假实现：建 mods 目录 -> 生成基线 ->
// 对账一致 -> 篡改 / 新增 / 缺失后分别检出，并覆盖路径净化、哈希格式、版本不
// 兼容与扫描上界。符号链接逃逸在 Windows 上创建链接需要特权，这里不依赖它，
// 用“深层子目录不纳入账本”的替代约束覆盖扫描边界。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestModAuditDetectsTamperAddRemove(t *testing.T) {
	mods, _ := buildTestModsDir(t)
	lim := defaultModAuditLimits()
	baseline, _, _, err := buildModAuditSnapshot([]string{mods}, lim)
	if err != nil {
		t.Fatalf("buildModAuditSnapshot 失败: %v", err)
	}

	// 篡改一个文件
	tampered := filepath.Join(mods, "coremod.jar")
	if err := os.WriteFile(tampered, []byte("evil payload"), 0o600); err != nil {
		t.Fatalf("篡改写入失败: %v", err)
	}
	// 删除一个文件
	if err := os.Remove(filepath.Join(mods, "library-1.20.jar")); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	// 新增一个文件
	if err := os.WriteFile(filepath.Join(mods, "newmod.jar"), []byte("fresh"), 0o600); err != nil {
		t.Fatalf("新增写入失败: %v", err)
	}

	current, _, _, err := buildModAuditSnapshot([]string{mods}, lim)
	if err != nil {
		t.Fatalf("buildModAuditSnapshot(当前) 失败: %v", err)
	}
	report := auditModsAgainstBaseline(current, baseline)
	if len(report.Tampered) != 1 || report.Tampered[0].RelPath != "coremod.jar" {
		t.Errorf("期望检出 1 个篡改 coremod.jar，得到 %+v", report.Tampered)
	}
	if len(report.Missing) != 1 || report.Missing[0].RelPath != "library-1.20.jar" {
		t.Errorf("期望检出 1 个缺失 library-1.20.jar，得到 %+v", report.Missing)
	}
	if len(report.Added) != 1 || report.Added[0].RelPath != "newmod.jar" {
		t.Errorf("期望检出 1 个新增 newmod.jar，得到 %+v", report.Added)
	}
	if !report.HasRisks {
		t.Errorf("存在风险时 HasRisks 应为 true")
	}
	// sub/addon.jar 未动，应计为一致
	if report.Consistent != 1 {
		t.Errorf("期望 1 个一致文件，得到 %d", report.Consistent)
	}
}

func TestModAuditNoBaselineMeansAllAdded(t *testing.T) {
	mods, _ := buildTestModsDir(t)
	current, _, _, err := buildModAuditSnapshot([]string{mods}, defaultModAuditLimits())
	if err != nil {
		t.Fatalf("buildModAuditSnapshot 失败: %v", err)
	}
	report := auditModsAgainstBaseline(current, nil)
	if len(report.Added) == 0 {
		t.Fatalf("无基线时应全量视为新增")
	}
	if len(report.Tampered) != 0 || len(report.Missing) != 0 {
		t.Errorf("无基线时不应有篡改/缺失误报: %+v", report)
	}
}

func TestModAuditBaselineSanitizeDropsDirty(t *testing.T) {
	dirty := `{
		"version": 1,
		"createdAt": "2026-10-11T00:00:00Z",
		"dirs": [
			{"dir": "mods", "entries": [
				{"relPath": "ok.jar", "name": "ok.jar", "size": 1, "umfs": "` + strings.Repeat("ab", 32) + `"},
				{"relPath": "../evil.jar", "name": "evil.jar", "size": 1, "umfs": "` + strings.Repeat("ab", 32) + `"},
				{"relPath": "badhash.jar", "name": "badhash.jar", "size": 1, "umfs": "nope"}
			]}
		]
	}`
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(dirty), 0o600); err != nil {
		t.Fatalf("写脏账本失败: %v", err)
	}
	loaded, err := loadModAuditSnapshot(path)
	if err != nil {
		t.Fatalf("loadModAuditSnapshot 失败: %v", err)
	}
	if loaded == nil || len(loaded.Dirs) != 1 {
		t.Fatalf("期望保留干净目录")
	}
	entries := loaded.Dirs[0].Entries
	if len(entries) != 1 || entries[0].RelPath != "ok.jar" {
		t.Errorf("脏条目应被丢弃，只留 ok.jar，得到 %+v", entries)
	}
}

func TestModAuditRejectsBadBaseline(t *testing.T) {
	// 版本不兼容
	badVer := `{"version": 99, "dirs": []}`
	p1 := filepath.Join(t.TempDir(), "badver.json")
	if err := os.WriteFile(p1, []byte(badVer), 0o600); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	if _, err := loadModAuditSnapshot(p1); err == nil {
		t.Errorf("版本不兼容应报错")
	}
	// 文件不存在 -> nil（首次基线语义）
	p2 := filepath.Join(t.TempDir(), "missing.json")
	loaded, err := loadModAuditSnapshot(p2)
	if err != nil {
		t.Errorf("不存在应返回 nil 而非错误: %v", err)
	}
	if loaded != nil {
		t.Errorf("不存在应返回 nil 基线")
	}
}

func TestModAuditScanBounds(t *testing.T) {
	dir := t.TempDir()
	mods := filepath.Join(dir, "mods")
	if err := os.MkdirAll(mods, 0o700); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(mods, "m"+string(rune('0'+i))+".jar"),
			[]byte("x"), 0o600); err != nil {
			t.Fatalf("写文件失败: %v", err)
		}
	}
	lim := ModAuditLimits{MaxEntries: 4, MaxEntryBytes: 1 << 20, MaxTotalBytes: 1 << 30}
	entries, skipped, limitHit, err := collectModAuditDir(mods, lim)
	if err != nil {
		t.Fatalf("collectModAuditDir 失败: %v", err)
	}
	if len(entries) > 4 {
		t.Errorf("条目数应受 MaxEntries 限制，得到 %d", len(entries))
	}
	if !limitHit {
		t.Errorf("触及条目上限时 limitHit 应为 true")
	}
	if skipped == 0 {
		t.Errorf("超出上限的条目应计入 skipped")
	}
}

func TestModAuditBaselineInfoText(t *testing.T) {
	info := &ModAuditBaselineInfo{Dirs: 2, TotalFiles: 13, Skipped: 1, LimitHit: false}
	text := modAuditBaselineInfoText(info)
	if !strings.Contains(text, "13") || !strings.Contains(text, "2 个目录") {
		t.Errorf("统计文案缺失关键数字: %q", text)
	}
}
