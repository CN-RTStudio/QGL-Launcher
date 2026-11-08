package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeWorldZip 造一个测试用世界 zip：entries 为 zip 条目名列表，mode 为可选文件模式。
func makeWorldZip(t *testing.T, entries []string, modes []os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "world.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for i, name := range entries {
		mode := os.FileMode(0o600)
		if len(modes) > i {
			mode = modes[i]
		}
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		hdr.SetMode(mode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create entry %s: %v", name, err)
		}
		if !hdr.Mode().IsDir() {
			w.Write([]byte("test-data-" + name))
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return zipPath
}

func TestInspectWorldZipSafe(t *testing.T) {
	zipPath := makeWorldZip(t, []string{"level.dat", "region/r.0.0.mca", "session.lock"}, nil)
	ins, err := inspectWorldZip(zipPath, defaultRestoreLimits())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !ins.Safe {
		t.Fatalf("expected safe, got %s", ins.Reason)
	}
	if !ins.HasLevel {
		t.Fatalf("expected level.dat detected")
	}
	if !ins.HasRegion {
		t.Fatalf("expected region detected")
	}
	if ins.EntryCount != 3 {
		t.Fatalf("expected 3 entries, got %d", ins.EntryCount)
	}
	if ins.TotalBytes <= 0 {
		t.Fatalf("expected positive total bytes")
	}
}

func TestInspectWorldZipZipSlip(t *testing.T) {
	zipPath := makeWorldZip(t, []string{"level.dat", "../evil.txt"}, nil)
	ins, err := inspectWorldZip(zipPath, defaultRestoreLimits())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if ins.Safe {
		t.Fatalf("expected zip-slip rejected")
	}
	if ins.Reason != "unsafe-path" {
		t.Fatalf("expected unsafe-path reason, got %s", ins.Reason)
	}
}

func TestInspectWorldZipSymlink(t *testing.T) {
	zipPath := makeWorldZip(t, []string{"level.dat", "link"}, []os.FileMode{0o600, os.ModeSymlink | 0o777})
	ins, err := inspectWorldZip(zipPath, defaultRestoreLimits())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if ins.Safe {
		t.Fatalf("expected symlink rejected")
	}
	if ins.Reason != "special-entry" {
		t.Fatalf("expected special-entry reason, got %s", ins.Reason)
	}
}

func TestInspectWorldZipMissingLevel(t *testing.T) {
	zipPath := makeWorldZip(t, []string{"readme.txt"}, nil)
	ins, err := inspectWorldZip(zipPath, defaultRestoreLimits())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !ins.Safe {
		t.Fatalf("expected structurally safe, got %s", ins.Reason)
	}
	if ins.HasLevel {
		t.Fatalf("expected hasLevel false")
	}
}

func TestImportExternalWorldZipRequiresLevel(t *testing.T) {
	savesDir := t.TempDir()
	// 缺 level.dat 的外部 zip 必须拒绝（不是完整世界）。
	zipPath := makeWorldZip(t, []string{"readme.txt"}, nil)
	if _, err := importExternalWorldZip(zipPath, savesDir, "imported", worldRestoreOptions{}); err == nil {
		t.Fatalf("expected reject for missing level.dat")
	} else if !strings.Contains(err.Error(), "level.dat") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImportExternalWorldZipSuccess(t *testing.T) {
	savesDir := t.TempDir()
	zipPath := makeWorldZip(t, []string{"level.dat", "region/r.0.0.mca", "data/scoreboard.dat"}, nil)
	meta, err := importExternalWorldZip(zipPath, savesDir, "imported", worldRestoreOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if meta.Action != "import" || meta.Entries != 3 {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if meta.DestDir != filepath.Join(savesDir, "imported") {
		t.Fatalf("unexpected dest: %s", meta.DestDir)
	}
	if _, err := os.Stat(filepath.Join(savesDir, "imported", "data", "scoreboard.dat")); err != nil {
		t.Fatalf("imported file missing: %v", err)
	}
	if meta.UMFS == "" {
		t.Fatalf("expected umfs fingerprint")
	}
}

func TestImportExternalWorldZipSlipRejected(t *testing.T) {
	savesDir := t.TempDir()
	zipPath := makeWorldZip(t, []string{"level.dat", "..\\escape.txt"}, nil)
	if _, err := importExternalWorldZip(zipPath, savesDir, "imp2", worldRestoreOptions{}); err == nil {
		t.Fatalf("expected zip-slip rejected")
	}
}

func TestImportExternalWorldZipOverwriteGuard(t *testing.T) {
	savesDir := t.TempDir()
	zipPath := makeWorldZip(t, []string{"level.dat"}, nil)
	if _, err := importExternalWorldZip(zipPath, savesDir, "world1", worldRestoreOptions{}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	// 未允许覆盖：拒绝。
	if _, err := importExternalWorldZip(zipPath, savesDir, "world1", worldRestoreOptions{}); err == nil {
		t.Fatalf("expected overwrite rejected")
	} else if !strings.Contains(err.Error(), "已存在") {
		t.Fatalf("unexpected error: %v", err)
	}
	// 允许覆盖：成功。
	meta, err := importExternalWorldZip(zipPath, savesDir, "world1", worldRestoreOptions{AllowOverwrite: true})
	if err != nil {
		t.Fatalf("import with overwrite: %v", err)
	}
	if meta.Entries != 1 {
		t.Fatalf("expected 1 entry, got %d", meta.Entries)
	}
}

func TestImportExternalWorldZipBadName(t *testing.T) {
	savesDir := t.TempDir()
	zipPath := makeWorldZip(t, []string{"level.dat"}, nil)
	for _, bad := range []string{"../escape", "a/b", "..", "", "world\x00name", "CON"} {
		if _, err := importExternalWorldZip(zipPath, savesDir, bad, worldRestoreOptions{}); err == nil {
			t.Fatalf("expected reject for name %q", bad)
		}
	}
}

func TestImportBombGuard(t *testing.T) {
	savesDir := t.TempDir()
	// 条目声明总量巨大（> 上限）→ 预检拒绝。
	zipPath := makeWorldZip(t, []string{"level.dat", "big.bin"}, nil)
	lim := defaultRestoreLimits()
	lim.TotalMax = 1 // 1 字节上限，任何真实内容都会超
	lim.EntryMax = 1
	if _, err := importExternalWorldZip(zipPath, savesDir, "bomb", worldRestoreOptions{Limits: lim}); err == nil {
		t.Fatalf("expected bomb guard reject")
	}
}

func TestImportZipPathMissing(t *testing.T) {
	savesDir := t.TempDir()
	if _, err := importExternalWorldZip(filepath.Join(t.TempDir(), "nope.zip"), savesDir, "w", worldRestoreOptions{}); err == nil {
		t.Fatalf("expected error for missing zip")
	}
}

func TestVerifyWorldRestore(t *testing.T) {
	savesDir := t.TempDir()
	zipPath := makeWorldZip(t, []string{"level.dat"}, nil)
	meta, err := importExternalWorldZip(zipPath, savesDir, "verified", worldRestoreOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	ok, note := verifyWorldRestore(meta.DestDir, "verified")
	if !ok {
		t.Fatalf("expected verify ok, got %s", note)
	}
	// 破坏 level.dat 后应验证失败。
	if err := os.Remove(filepath.Join(meta.DestDir, "level.dat")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if ok, _ := verifyWorldRestore(meta.DestDir, "verified"); ok {
		t.Fatalf("expected verify fail after removal")
	}
	// 目录与名称不一致应失败。
	if ok, _ := verifyWorldRestore(meta.DestDir, "othername"); ok {
		t.Fatalf("expected verify fail on name mismatch")
	}
}

func TestResolveRestoreDestWithinRoot(t *testing.T) {
	savesDir := t.TempDir()
	dest, err := resolveRestoreDest(savesDir, "world")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !PathWithinRoot(dest, savesDir) {
		t.Fatalf("dest outside root")
	}
	if _, err := resolveRestoreDest(savesDir, "../up"); err == nil {
		t.Fatalf("expected reject for traversal name")
	}
}

// TestImportUMFSStable 验证相同 zip 导入两次（不同根）得到相同目录指纹。
func TestImportUMFSStable(t *testing.T) {
	zipPath := makeWorldZip(t, []string{"level.dat", "region/r.0.0.mca"}, nil)
	m1, err := importExternalWorldZip(zipPath, t.TempDir(), "w", worldRestoreOptions{})
	if err != nil {
		t.Fatalf("import1: %v", err)
	}
	m2, err := importExternalWorldZip(zipPath, t.TempDir(), "w", worldRestoreOptions{})
	if err != nil {
		t.Fatalf("import2: %v", err)
	}
	if m1.UMFS == "" || m1.UMFS != m2.UMFS {
		t.Fatalf("expected stable umfs, got %q vs %q", m1.UMFS, m2.UMFS)
	}
}

// TestNormalizeRestoreLimits 验证上限归一化边界。
func TestNormalizeRestoreLimits(t *testing.T) {
	z := normalizeRestoreLimits(RestoreLimits{})
	if z.EntryMax != worldMaxEntryCeiling || z.TotalMax != worldMaxTotalCeiling {
		t.Fatalf("defaults not applied: %+v", z)
	}
	over := normalizeRestoreLimits(RestoreLimits{EntryMax: 1 << 62, TotalMax: 1 << 62, MaxEntries: 0})
	if over.EntryMax > worldMaxEntryCeiling || over.TotalMax > worldMaxTotalCeiling || over.MaxEntries <= 0 {
		t.Fatalf("ceiling not applied: %+v", over)
	}
	shrunk := normalizeRestoreLimits(RestoreLimits{EntryMax: 100, TotalMax: 50, MaxEntries: 5})
	if shrunk.EntryMax != 50 {
		t.Fatalf("entryMax not shrunk to totalMax: %+v", shrunk)
	}
}
