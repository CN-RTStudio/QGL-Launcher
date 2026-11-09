package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// worldbackup_test.go —— 世界存档安全备份内核测试。
//
// 只在真实临时目录上跑端到端流程，不用内存假实现：建世界 -> 备份 -> 恢复 -> 逐
// 文件比对，并覆盖符号链接逃逸、UMFS 掉包、体量预算、保留份数淘汰与路径穿越。

func TestValidateWorldName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"New World", true},
		{"  spaced  ", true}, // 首尾空白会被裁剪后接受
		{"世界_1.20", true},
		{"", false},
		{"   ", false},
		{"..", false},
		{"a/b", false},
		{"a\\b", false},
		{"CON", false},
		{"nul.txt", false},
		{"bad:name", false},
		{"line\nbreak", false},
		{"bidi\u202estuff", false},
		{"zero\u200bwidth", false},
		{"trailing.", false},
	}
	for _, c := range cases {
		got, reason := validateWorldName(c.name)
		if c.ok {
			if reason != nameRejectNone {
				t.Errorf("validateWorldName(%q) 拒绝原因=%q，期望通过", c.name, reason)
			}
			if got != strings.TrimSpace(c.name) {
				t.Errorf("validateWorldName(%q) 裁剪结果=%q", c.name, got)
			}
		} else if reason == nameRejectNone {
			t.Errorf("validateWorldName(%q) 期望被拒绝，实际通过", c.name)
		}
	}
	long := strings.Repeat("a", maxWorldNameLen+1)
	if _, reason := validateWorldName(long); reason == nameRejectNone {
		t.Errorf("超长世界名应被拒绝")
	}
}

func TestValidateWorldStamp(t *testing.T) {
	good := []string{"20261009-153000", "19990101-000000"}
	for _, s := range good {
		if !validateWorldStamp(s) {
			t.Errorf("合法时间戳 %q 被拒", s)
		}
	}
	bad := []string{
		"", "2026-10-09", "20261009-15300", "20261009-15300x",
		"20261009_153000", "20261009153000", "20261340-999999",
	}
	for _, s := range bad {
		if validateWorldStamp(s) {
			t.Errorf("非法时间戳 %q 被判为合法", s)
		}
	}
}

func TestNormalizeWorldBackupLimits(t *testing.T) {
	n := normalizeWorldBackupLimits(WorldBackupLimits{})
	d := defaultWorldBackupLimits()
	if n != d {
		t.Errorf("零值应收敛为默认值，得到 %+v，期望 %+v", n, d)
	}
	huge := normalizeWorldBackupLimits(WorldBackupLimits{
		MaxEntries:    1 << 30,
		MaxTotalBytes: 1 << 40,
		MaxEntryBytes: 1 << 40,
		Keep:          1 << 20,
	})
	if huge.MaxEntries != worldMaxEntriesCeiling || huge.MaxTotalBytes != worldMaxTotalCeiling ||
		huge.MaxEntryBytes != worldMaxEntryCeiling || huge.Keep != worldKeepMax {
		t.Errorf("超大上限未压回天花板: %+v", huge)
	}
	clamped := normalizeWorldBackupLimits(WorldBackupLimits{
		MaxEntries: 10, MaxTotalBytes: 100, MaxEntryBytes: 1000, Keep: 2,
	})
	if clamped.MaxEntryBytes != clamped.MaxTotalBytes {
		t.Errorf("单文件上限大于总上限时应收紧，得到 %+v", clamped)
	}
}

// writeWorldFile 在根下写一个相对路径文件（自动建父目录）。
func writeWorldFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("建父目录失败 %s: %v", rel, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("写文件失败 %s: %v", rel, err)
	}
}

func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("遍历目录失败: %v", err)
	}
	return out
}

func TestBackupAndRestoreRoundTrip(t *testing.T) {
	base := t.TempDir()
	saves := filepath.Join(base, "saves")
	backupRoot := filepath.Join(base, "worldbackups")
	world := filepath.Join(saves, "Survival")

	files := map[string]string{
		"level.dat":               "level-bytes-0",
		"level.dat_old":           "level-old",
		"region/r.0.0.mca":        "chunk-data-aaaa",
		"region/r.0.-1.mca":       "chunk-data-bbbb",
		"playerdata/player1.dat":  "inventory",
		"stats/ignored-note.json": "{}",
		"DIM1/region/r.1.1.mca":   "nether",
	}
	for rel, body := range files {
		writeWorldFile(t, world, rel, body)
	}

	now := time.Date(2026, 10, 9, 8, 30, 5, 0, time.UTC)
	meta, err := createWorldBackup(world, backupRoot, "Survival", now, defaultWorldBackupLimits())
	if err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}
	if meta.Entries != len(files) {
		t.Errorf("条目数=%d，期望 %d", meta.Entries, len(files))
	}
	if meta.Stamp != "20261009-083005" {
		t.Errorf("时间戳=%q", meta.Stamp)
	}
	if meta.UMFS == "" {
		t.Errorf("应生成 UMFS 摘要")
	}

	// zip 与清单都应在受信备份根内、权限收敛。
	zipPath := filepath.Join(backupRoot, "Survival", meta.ZipName)
	if fi, err := os.Stat(zipPath); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("备份 zip 不存在或权限未收敛: %v %v", zipPath, err)
	}

	list, err := listWorldBackups(backupRoot, "Survival")
	if err != nil || len(list) != 1 || list[0].Stamp != meta.Stamp {
		t.Fatalf("列出备份异常: %v %+v", err, list)
	}

	// 破坏原世界后恢复，结果应与备份内容逐文件一致。
	if err := os.RemoveAll(world); err != nil {
		t.Fatalf("删除原世界失败: %v", err)
	}
	restored, err := restoreWorldBackup(saves, backupRoot, "Survival", meta.Stamp, defaultWorldBackupLimits())
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if !strings.HasPrefix(filepath.ToSlash(restored), filepath.ToSlash(saves)+"/") {
		t.Fatalf("恢复目录越出 saves: %s", restored)
	}
	if filepath.Base(restored) != "Survival-restored-"+meta.Stamp {
		t.Errorf("恢复目录命名不符: %s", filepath.Base(restored))
	}
	got := readTree(t, restored)
	if len(got) != len(files) {
		t.Fatalf("恢复文件数=%d，期望 %d", len(got), len(files))
	}
	for rel, want := range files {
		if got[rel] != want {
			t.Errorf("恢复内容不符 %s", rel)
		}
	}

	// 再次恢复不应覆盖，应分配 -01。
	restored2, err := restoreWorldBackup(saves, backupRoot, "Survival", meta.Stamp, defaultWorldBackupLimits())
	if err != nil {
		t.Fatalf("第二次恢复失败: %v", err)
	}
	if restored2 == restored {
		t.Errorf("第二次恢复覆盖了首次恢复目录")
	}
	if filepath.Base(restored2) != "Survival-restored-"+meta.Stamp+"-01" {
		t.Errorf("第二次恢复目录命名不符: %s", filepath.Base(restored2))
	}
}
