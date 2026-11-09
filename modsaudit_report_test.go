package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
