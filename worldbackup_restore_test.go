package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestRestoreRejectsTamperedZip(t *testing.T) {
	base := t.TempDir()
	saves := filepath.Join(base, "saves")
	backupRoot := filepath.Join(base, "worldbackups")
	world := filepath.Join(saves, "W")
	writeWorldFile(t, world, "level.dat", "data")

	meta, err := createWorldBackup(world, backupRoot, "W", time.Now().UTC(), defaultWorldBackupLimits())
	if err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}
	zipPath := filepath.Join(backupRoot, "W", meta.ZipName)
	// 在 zip 末尾追加脏字节，UMFS 摘要必然变化。
	f, err := os.OpenFile(zipPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("打开备份用于篡改: %v", err)
	}
	if _, err := f.WriteString("TAMPER"); err != nil {
		t.Fatalf("篡改备份失败: %v", err)
	}
	f.Close()

	if _, err := restoreWorldBackup(saves, backupRoot, "W", meta.Stamp, defaultWorldBackupLimits()); err == nil {
		t.Fatalf("UMFS 不一致的备份应被拒绝恢复")
	}
}

func TestBackupRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	world := filepath.Join(base, "saves", "W")
	outside := filepath.Join(base, "outside.txt")
	writeWorldFile(t, base, "outside.txt", "secret")
	writeWorldFile(t, world, "level.dat", "data")
	// 世界内埋一个指向 saves 之外文件的符号链接。
	link := filepath.Join(world, "evil.lnk")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("当前环境不支持创建符号链接: %v", err)
	}
	backupRoot := filepath.Join(base, "worldbackups")
	if _, err := createWorldBackup(world, backupRoot, "W", time.Now().UTC(), defaultWorldBackupLimits()); err == nil {
		t.Fatalf("含越界符号链接的世界应被拒绝备份")
	}
	if _, err := os.Stat(backupRoot); err == nil {
		// 失败后不应留下任何备份 zip。
		if entries, _ := os.ReadDir(filepath.Join(backupRoot, "W")); len(entries) != 0 {
			t.Errorf("失败后残留备份文件: %v", entries)
		}
	}
}

func TestBackupEnforcesLimits(t *testing.T) {
	base := t.TempDir()
	world := filepath.Join(base, "saves", "W")
	// 10 个文件，每个 1024 字节。
	for i := 0; i < 10; i++ {
		writeWorldFile(t, world, "f"+itoaModName(i)+".dat", strings.Repeat("x", 1024))
	}
	backupRoot := filepath.Join(base, "worldbackups")

	smallEntry := defaultWorldBackupLimits()
	smallEntry.MaxEntryBytes = 512
	smallEntry.MaxTotalBytes = 4096
	if _, err := createWorldBackup(world, backupRoot, "W", time.Now().UTC(), smallEntry); err == nil {
		t.Errorf("超过单文件上限应失败")
	}

	smallTotal := defaultWorldBackupLimits()
	smallTotal.MaxTotalBytes = 4096
	smallTotal.MaxEntryBytes = 1 << 20
	if _, err := createWorldBackup(world, backupRoot, "W2", time.Now().UTC(), smallTotal); err == nil {
		// 注意世界名要不同以复用同一备份根；总量 10KiB > 4KiB。
		t.Errorf("超过总体积上限应失败")
	}

	fewEntries := defaultWorldBackupLimits()
	fewEntries.MaxEntries = 3
	if _, err := createWorldBackup(world, backupRoot, "W3", time.Now().UTC(), fewEntries); err == nil {
		t.Errorf("超过条目数上限应失败")
	}
}

func TestPruneWorldBackupsKeepsNewest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wb", "W")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("建备份目录失败: %v", err)
	}
	stamps := []string{
		"20261001-000000", "20261002-000000", "20261003-000000",
		"20261004-000000", "20261005-000000",
	}
	for _, s := range stamps {
		writeWorldFile(t, dir, s+".zip", "zip")
		writeWorldFile(t, dir, s+".json", "{}")
	}
	// 无关文件与不合规时间戳不应被动到。
	writeWorldFile(t, dir, "note.txt", "keep")
	writeWorldFile(t, dir, "20261006-bad.zip", "keep")

	removed, err := pruneWorldBackups(dir, 3)
	if err != nil {
		t.Fatalf("淘汰旧备份失败: %v", err)
	}
	if removed != 2 {
		t.Errorf("淘汰数=%d，期望 2", removed)
	}
	kept, _ := os.ReadDir(dir)
	names := make([]string, 0, len(kept))
	for _, e := range kept {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	want := []string{
		"20261003-000000.json", "20261003-000000.zip",
		"20261004-000000.json", "20261004-000000.zip",
		"20261005-000000.json", "20261005-000000.zip",
		"20261006-bad.zip", "note.txt",
	}
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("淘汰后文件集不符:\n%v", names)
	}
}

func TestAllocateRestoreDirRejectsTraversal(t *testing.T) {
	saves := filepath.Join(t.TempDir(), "saves")
	bad := []string{"../evil", "a/b", "CON", "x\\y", ""}
	for _, name := range bad {
		if _, err := allocateRestoreDir(saves, name, "20261009-120000"); err == nil {
			t.Errorf("非法世界名 %q 不应分配恢复目录", name)
		}
	}
	if _, err := allocateRestoreDir(saves, "W", "bad-stamp"); err == nil {
		t.Errorf("非法时间戳不应分配恢复目录")
	}
	dir1, err := allocateRestoreDir(saves, "W", "20261009-120000")
	if err != nil {
		t.Fatalf("首次分配失败: %v", err)
	}
	if err := os.MkdirAll(dir1, 0o700); err != nil {
		t.Fatalf("占位失败: %v", err)
	}
	dir2, err := allocateRestoreDir(saves, "W", "20261009-120000")
	if err != nil {
		t.Fatalf("冲突时再次分配失败: %v", err)
	}
	if dir1 == dir2 {
		t.Errorf("目录已存在时应分配唯一名")
	}
}

func TestWorldBackupDirForRejectsBadName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "worldbackups")
	for _, name := range []string{"../x", "a/b", "NUL", "has space/"} {
		if _, err := worldBackupDirFor(root, name); err == nil {
			t.Errorf("非法世界名 %q 不应解析出备份目录", name)
		}
	}
	dir, err := worldBackupDirFor(root, "Ok")
	if err != nil {
		t.Fatalf("合法世界名解析失败: %v", err)
	}
	if !strings.HasPrefix(filepath.ToSlash(dir), filepath.ToSlash(root)+"/") {
		t.Errorf("备份目录越界: %s", dir)
	}
}
