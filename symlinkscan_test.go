package main

// symlinkscan_test.go —— 符号链接扫描内核测试。
//
// Windows 上创建符号链接需要特权/开发者模式，测试不依赖真实链接：
// 用“伪造陷阱列表”测摘要与排序，用普通目录测零命中与深度/条目上限，
// platformSymlinkCheck 本身由 launchpreflight 测试覆盖（同原语）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSymlinkTrapsCleanTree(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "mods", "fabric")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sub, "a.jar"), []byte("x"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "versions", "1.21", "1.21.json"), []byte("{}"), 0644)
	if err := os.MkdirAll(filepath.Join(dir, "versions", "1.21"), 0755); err != nil {
		t.Fatal(err)
	}
	traps, err := scanSymlinkTraps(dir)
	if err != nil {
		t.Fatalf("干净目录不应报错: %v", err)
	}
	if len(traps) != 0 {
		t.Fatalf("干净目录不应命中陷阱: %+v", traps)
	}
}

func TestScanSymlinkTrapsDetectsLink(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	// 创建真实符号链接（Windows 上如无权限则跳过该用例）。
	target := filepath.Join(outside, "evil.dll")
	_ = os.WriteFile(target, []byte("PE"), 0644)
	link := filepath.Join(dir, "mods", "evil.dll")
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境不允许创建符号链接: %v", err)
	}
	traps, err := scanSymlinkTraps(dir)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(traps) != 1 {
		t.Fatalf("应命中 1 个陷阱, 实际 %d: %+v", len(traps), traps)
	}
	if !strings.HasSuffix(traps[0].Path, "mods/evil.dll") {
		t.Fatalf("陷阱相对路径不符: %q", traps[0].Path)
	}
}

func TestScanSymlinkTrapsDirLinkNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "versions")); err != nil {
		t.Skipf("当前环境不允许创建符号链接: %v", err)
	}
	traps, err := scanSymlinkTraps(dir)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(traps) != 1 {
		t.Fatalf("目录链接应命中 1 个陷阱且不跟随进入: %d", len(traps))
	}
}

func TestSymlinkTrapSummary(t *testing.T) {
	traps := []symlinkTrap{
		{Path: "mods/a.jar", Target: "C:\\evil\\a.jar"},
		{Path: "versions/x"},
	}
	sum := symlinkTrapSummary(traps, 0)
	if len(sum) != 2 {
		t.Fatalf("摘要应 2 条: %d", len(sum))
	}
	if sum[0] != "mods/a.jar -> C:\\evil\\a.jar" {
		t.Fatalf("带目标摘要不符: %q", sum[0])
	}
	if sum[1] != "versions/x" {
		t.Fatalf("无目标摘要不符: %q", sum[1])
	}
	if symlinkTrapSummary(nil, 0) != nil {
		t.Fatal("空列表应返回 nil")
	}
}

func TestSymlinkTrapSummaryLimit(t *testing.T) {
	traps := make([]symlinkTrap, 30)
	for i := range traps {
		traps[i] = symlinkTrap{Path: "p" + string(rune('a'+i%26)) + string(rune('0'+i%10))}
	}
	sum := symlinkTrapSummary(traps, 5)
	if len(sum) != 5 {
		t.Fatalf("limit=5 应返回 5 条: %d", len(sum))
	}
}

func TestSymlinkTrapSummaryMaxCap(t *testing.T) {
	traps := make([]symlinkTrap, 100)
	for i := range traps {
		traps[i] = symlinkTrap{Path: "p" + strings.Repeat("x", i%3) + "i"}
	}
	sum := symlinkTrapSummary(traps, 0)
	if len(sum) > maxSymlinkTrapReports {
		t.Fatalf("摘要不应超过 %d 条: %d", maxSymlinkTrapReports, len(sum))
	}
}
