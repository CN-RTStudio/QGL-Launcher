package main

// screenshotguard_test.go —— 截图文件名/目录校验内核的测试。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeScreenshotName(t *testing.T) {
	var lim0 ScreenshotLimits
	lim := lim0.withDefaults()
	good := []string{
		"2026-10-11_22-30-05.png",
		"我的世界-生存-第3张.jpg",
		"screen_001.png",
		"server name 1.png",
		"CONfig.png",
	}
	bad := []string{
		"",
		"   ",
		strings.Repeat("a", 300) + ".png",
		"shot\x00x.png",
		"../../evil.png",
		"sub/dir.png",
		"sub\\dir.png",
		"a..b.png",
		"CON.png",
		"PRN.txt",
		"AUX",
		"NUL",
		"COM1.png",
		"LPT9.jpg",
		"CON5.png",
		"CON.txt",
		"a<b.png",
		"a:b.png",
		"a|b.png",
		"a?b.png",
		"a*b.png",
		"a\"b.png",
		".",
		"..",
	}
	for _, n := range good {
		if _, err := SanitizeScreenshotName(n, lim); err != nil {
			t.Errorf("name %q rejected: %v", n, err)
		}
	}
	for _, n := range bad {
		if _, err := SanitizeScreenshotName(n, lim); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

func TestSanitizeScreenshotNameAllowSubdirs(t *testing.T) {
	var lim0 ScreenshotLimits
	lim := lim0.withDefaults()
	lim.AllowSubdirs = true
	if _, err := SanitizeScreenshotName("sub/dir.png", lim); err != nil {
		t.Errorf("subdir name should pass with AllowSubdirs: %v", err)
	}
	if _, err := SanitizeScreenshotName("../../evil.png", lim); err == nil {
		t.Error("parent traversal must be rejected even with AllowSubdirs")
	}
	// 中间段穿越、绝对路径、空段、当前目录点段都要拒；子目录里的设备名按末段拒。
	bad := []string{
		"sub/../../evil.png",
		"/abs/path.png",
		`\abs\path.png`,
		"a//b.png",
		"sub/./ok.png",
		"sub/CON.png",
		`dir\..\evil.png`,
	}
	for _, n := range bad {
		if _, err := SanitizeScreenshotName(n, lim); err == nil {
			t.Errorf("AllowSubdirs name %q should be rejected", n)
		}
	}
}

func TestIsWinReservedName(t *testing.T) {
	yes := []string{"CON", "con", "CON.png", "PRN.txt", "AUX", "NUL", "COM1", "com9.jpg", "LPT3", "CON5", "CON.txt"}
	no := []string{"Config", "CONfig", "Computer", "Comb", "CONsole", "comic"}
	for _, n := range yes {
		if !isWinReservedName(n) {
			t.Errorf("%q should be reserved", n)
		}
	}
	for _, n := range no {
		if isWinReservedName(n) {
			t.Errorf("%q should not be reserved", n)
		}
	}
}

func TestValidateScreenshotDir(t *testing.T) {
	var lim0 ScreenshotLimits
	lim := lim0.withDefaults()
	root := t.TempDir()
	realDir := filepath.Join(root, "shots")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateScreenshotDir(realDir, root, lim); err != nil {
		t.Errorf("valid dir rejected: %v", err)
	}
	bad := []string{
		"",
		strings.Repeat("a", 5000),
		"bad\x00dir",
		`\\server\share`,
		"relative/dir",
		filepath.Join(root, "shots", "..", "..", ".."),
		filepath.Join(root, "missing"),
	}
	for _, p := range bad {
		if _, err := ValidateScreenshotDir(p, root, lim); err == nil {
			t.Errorf("bad dir %q accepted", p)
		}
	}
	// 逃逸允许根
	other := t.TempDir()
	esc := filepath.Join(other, "elsewhere")
	if err := os.MkdirAll(esc, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateScreenshotDir(esc, root, lim); err == nil {
		t.Error("dir outside allowRoot accepted")
	}
}

func TestBuildScreenshotPath(t *testing.T) {
	var lim0 ScreenshotLimits
	lim := lim0.withDefaults()
	root := t.TempDir()
	dir := filepath.Join(root, "shots")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	full, err := BuildScreenshotPath(dir, "a.png", root, lim)
	if err != nil {
		t.Fatalf("valid build rejected: %v", err)
	}
	if full != filepath.Join(dir, "a.png") {
		t.Errorf("unexpected path: %s", full)
	}
	if _, err := BuildScreenshotPath(dir, "CON.png", root, lim); err == nil {
		t.Error("reserved name build accepted")
	}
	if _, err := BuildScreenshotPath(dir, "ok.png", filepath.Join(t.TempDir()), lim); err == nil {
		t.Error("escape build accepted")
	}
}

func TestSummarizeScreenshotError(t *testing.T) {
	if s := SummarizeScreenshotError(nil); s != "screenshot path ok" {
		t.Errorf("unexpected ok summary: %s", s)
	}
	if s := SummarizeScreenshotError(errTest("bad")); !strings.Contains(s, "rejected") {
		t.Errorf("unexpected err summary: %s", s)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
