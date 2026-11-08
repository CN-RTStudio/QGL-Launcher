package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeExtOK(t *testing.T) {
	good := []string{"lwjgl.dll", "libglfw.so", "libgl.dylib", "natives.json", "readme.txt"}
	for _, s := range good {
		if !nativeExtOK(s) {
			t.Fatalf("%q rejected", s)
		}
	}
	bad := []string{"evil.exe", "run.bat", "shell.sh", "noext", "a.jar", "x.vbs"}
	for _, s := range bad {
		if nativeExtOK(s) {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestScanNativesDir(t *testing.T) {
	lim := defaultNativeLimits()
	root := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("lwjgl.dll")
	write("libglfw.so")
	write("natives.json")
	vd := ScanNativesDir(root, lim)
	if !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}
	if len(vd.Entries) != 3 {
		t.Fatalf("entries=%d want 3", len(vd.Entries))
	}

	// 坏扩展名
	os.WriteFile(filepath.Join(root, "evil.exe"), []byte("x"), 0o644)
	vd = ScanNativesDir(root, lim)
	if vd.OK || vd.Reason != "ext:evil.exe" {
		t.Fatalf("exe accepted: %v", vd)
	}
	os.Remove(filepath.Join(root, "evil.exe"))

	// 隐藏文件
	os.WriteFile(filepath.Join(root, ".hidden"), []byte("x"), 0o644)
	vd = ScanNativesDir(root, lim)
	if vd.OK || vd.Reason != "hidden-file:.hidden" {
		t.Fatalf("hidden accepted: %v", vd)
	}
	os.Remove(filepath.Join(root, ".hidden"))

	// 符号链接
	if err := os.Symlink("lwjgl.dll", filepath.Join(root, "link.dll")); err == nil {
		vd = ScanNativesDir(root, lim)
		if vd.OK || vd.Reason != "symlink:link.dll" {
			t.Fatalf("symlink accepted: %v", vd)
		}
	}
}

func TestScanNativesOverflow(t *testing.T) {
	lim := defaultNativeLimits()
	lim.MaxEntries = 1
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.dll"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "b.dll"), []byte("x"), 0o644)
	vd := ScanNativesDir(root, lim)
	if vd.OK || vd.Reason != "entries-overflow" {
		t.Fatalf("overflow: %v", vd)
	}
}

func TestSummarizeNativeVerdict(t *testing.T) {
	if s := SummarizeNativeVerdict(nativeVerdict{OK: true, Entries: []nativeEntry{{Name: "a.dll"}}}); s != "natives ok entries=1" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeNativeVerdict(nativeVerdict{OK: false, Reason: "ext:evil.exe"}); s != "natives bad ext:evil.exe" {
		t.Fatalf("summary wrong: %q", s)
	}
}
