package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

type zipEntrySpec struct {
	name string
	data []byte
	mode os.FileMode
}

func writeTestZip(t *testing.T, path string, entries []zipEntrySpec) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			hdr.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("zip header %q: %v", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatalf("zip body %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
}

func TestExtractNativesNormal(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "natives.jar")
	dest := filepath.Join(dir, "out")
	writeTestZip(t, jar, []zipEntrySpec{
		{name: "a.dll", data: []byte("AAAAA")},
		{name: "sub/b.so", data: []byte("BBBB")},
		{name: "META-INF/MANIFEST.MF", data: []byte("skip")},
		{name: "readme.txt", data: []byte("skip")},
	})
	n, err := extractNatives(jar, dest)
	if err != nil {
		t.Fatalf("extractNatives: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 native files, got %d", n)
	}
	for _, name := range []string{"a.dll", "b.so"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("missing extracted %s: %v", name, err)
		}
	}
}

// 超过单文件上限的条目必须中止并报错，且不得在目标目录留下任何输出文件。
// 用可注入阈值的内核 + 小上限（16B）验证体积边界，不必真造几百 MiB 数据；
// 数据体 38B > 16B，解压必须中止。
func TestExtractNativesRejectsOversizedEntry(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "big.jar")
	dest := filepath.Join(dir, "out")
	writeTestZip(t, jar, []zipEntrySpec{
		{name: "huge.dll", data: []byte("this-is-way-longer-than-16-bytes!!")},
	})
	n, err := extractNativesWithLimits(jar, dest, 16, 4096)
	if err == nil {
		t.Fatal("expected error for oversized native entry, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(dest, "huge.dll")); !os.IsNotExist(statErr) {
		t.Fatalf("oversized entry must not be written, stat=%v", statErr)
	}
	if n != 0 {
		t.Fatalf("expected 0 extracted files on abort, got %d", n)
	}
}

// 多个小文件累计超过总量上限时也要中止，堵住“每个文件都不大但数量巨大”的总量型 zip 炸弹。
func TestExtractNativesRejectsTotalOverflow(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "total.jar")
	dest := filepath.Join(dir, "out")
	writeTestZip(t, jar, []zipEntrySpec{
		{name: "a.dll", data: []byte("aaaaaaaa")}, // 8
		{name: "b.dll", data: []byte("bbbbbbbb")}, // 8
		{name: "c.dll", data: []byte("cccccccc")}, // 8 → 累计 24 > 20
	})
	if _, err := extractNativesWithLimits(jar, dest, 16, 20); err == nil {
		t.Fatal("expected error when cumulative size exceeds total limit")
	}
}

// 伪装成 .dll 的符号链接条目必须被跳过，不能落地。
func TestExtractNativesSkipsSymlinkEntry(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "link.jar")
	dest := filepath.Join(dir, "out")
	writeTestZip(t, jar, []zipEntrySpec{
		{name: "real.dll", data: []byte("ok")},
		{name: "evil.dll", data: []byte("../outside"), mode: os.ModeSymlink | 0o644},
	})
	n, err := extractNatives(jar, dest)
	if err != nil {
		t.Fatalf("extractNatives: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected only 1 real file (symlink skipped), got %d", n)
	}
	if _, err := os.Lstat(filepath.Join(dest, "evil.dll")); !os.IsNotExist(err) {
		t.Fatalf("symlink entry must not be extracted, lstat=%v", err)
	}
}

func TestCopyDirContentsSkipsSymlink(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.dll")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "good.dll"), []byte("good"), 0o600); err != nil {
		t.Fatalf("write good: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "link.dll")); err != nil {
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}
	if err := copyDirContents(src, dst); err != nil {
		t.Fatalf("copyDirContents: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "good.dll")); err != nil {
		t.Errorf("regular file should be copied: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "link.dll")); !os.IsNotExist(err) {
		t.Errorf("symlink must not be copied into runtime dir, lstat=%v", err)
	}
}
