package main

// launchpreflight_test.go —— 启动预检纯函数单测。
//
// 覆盖：Java 路径缺文件 / 目录 / 控制字符 / 空名；游戏目录缺失；natives 空目录
// warning；磁盘余量告警；聚合 critical 阻断逻辑。全部用临时目录造真实文件，
// 不 mock 文件系统（“排查 bug 必须实际运行验证”口径）。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckJavaBinaryRejectsMissing(t *testing.T) {
	issues := checkJavaBinary(filepath.Join(t.TempDir(), "no-such-java.exe"))
	if len(issues) == 0 || issues[0].Kind != preflightCritical {
		t.Fatalf("缺文件应报 critical: %+v", issues)
	}
}

func TestCheckJavaBinaryRejectsDir(t *testing.T) {
	issues := checkJavaBinary(t.TempDir())
	found := false
	for _, it := range issues {
		if it.Code == "java-path-is-dir" {
			found = true
		}
	}
	if !found {
		t.Fatalf("目录路径应报 java-path-is-dir: %+v", issues)
	}
}

func TestCheckJavaBinaryRejectsControlChars(t *testing.T) {
	issues := checkJavaBinary("C:\\evil\x00java.exe")
	if len(issues) == 0 || issues[0].Code != "java-path-unsafe" {
		t.Fatalf("控制字符应报 java-path-unsafe: %+v", issues)
	}
}

func TestCheckJavaBinaryAcceptsRegularFile(t *testing.T) {
	dir := t.TempDir()
	javaPath := filepath.Join(dir, "java.exe")
	if err := os.WriteFile(javaPath, []byte("MZ"), 0755); err != nil {
		t.Fatal(err)
	}
	if issues := checkJavaBinary(javaPath); len(issues) != 0 {
		t.Fatalf("常规文件不应有 issues: %+v", issues)
	}
}

func TestCheckJavaBinaryRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.exe")
	if err := os.WriteFile(target, []byte("MZ"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "java-link.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("环境不支持符号链接，跳过: %v", err)
	}
	issues := checkJavaBinary(link)
	found := false
	for _, it := range issues {
		if it.Code == "java-path-symlink" {
			found = true
		}
	}
	if !found {
		t.Fatalf("符号链接应报 java-path-symlink: %+v", issues)
	}
}

func TestCheckGameDirs(t *testing.T) {
	base := t.TempDir()
	gameDir := filepath.Join(base, "game")
	if err := os.MkdirAll(gameDir, 0755); err != nil {
		t.Fatal(err)
	}
	// 正常：两者都在，natives 非空 → 无 issues。
	nativesDir := filepath.Join(base, "natives")
	if err := os.MkdirAll(nativesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nativesDir, "x.dll"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if issues := checkGameDirs(gameDir, nativesDir); len(issues) != 0 {
		t.Fatalf("正常目录不应有 issues: %+v", issues)
	}
	// natives 为空 → warning natives-empty。
	emptyNatives := filepath.Join(base, "empty-natives")
	if err := os.MkdirAll(emptyNatives, 0755); err != nil {
		t.Fatal(err)
	}
	issues := checkGameDirs(gameDir, emptyNatives)
	found := false
	for _, it := range issues {
		if it.Code == "natives-empty" && it.Kind == preflightWarning {
			found = true
		}
	}
	if !found {
		t.Fatalf("空 natives 应报 warning: %+v", issues)
	}
	// 游戏目录缺失 → critical。
	if issues := checkGameDirs(filepath.Join(base, "missing-game"), nativesDir); len(issues) == 0 ||
		issues[0].Code != "gamedir-missing" {
		t.Fatalf("缺游戏目录应报 critical: %+v", issues)
	}
}

func TestAggregatePreflightBlocksOnCritical(t *testing.T) {
	warn := []PreflightIssue{{Kind: preflightWarning, Code: "disk-low", Field: "disk", Text: "空间低"}}
	crit := []PreflightIssue{{Kind: preflightCritical, Code: "java-path-missing", Field: "java", Text: "缺"}}
	all, blocked := aggregatePreflight(warn, crit)
	if !blocked || len(all) != 2 {
		t.Fatalf("critical 应阻断且聚合全部: blocked=%v len=%d", blocked, len(all))
	}
	all, blocked = aggregatePreflight(warn)
	if blocked || len(all) != 1 {
		t.Fatalf("纯 warning 不应阻断: blocked=%v len=%d", blocked, len(all))
	}
}

func TestCheckSymlinkTrapsCleanAndTrap(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "mods"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "mods", "a.jar"), []byte("x"), 0600)
	if issues := checkSymlinkTraps(dir); len(issues) != 0 {
		t.Fatalf("干净目录不应有 issues: %+v", issues)
	}
	// 挂一个真实符号链接 → critical。
	outside := filepath.Join(t.TempDir(), "evil.jar")
	_ = os.WriteFile(outside, []byte("x"), 0600)
	if err := os.Symlink(outside, filepath.Join(dir, "mods", "evil.jar")); err != nil {
		t.Skipf("当前环境不允许创建符号链接: %v", err)
	}
	issues := checkSymlinkTraps(dir)
	if len(issues) != 1 || issues[0].Kind != preflightCritical || issues[0].Code != "symlink-trap" {
		t.Fatalf("应命中 critical 陷阱: %+v", issues)
	}
	if issues[0].Text == "" {
		t.Fatal("陷阱说明不应为空")
	}
}

func TestTruncatePreflightText(t *testing.T) {
	short := truncatePreflightText("abc")
	if short != "abc" {
		t.Fatalf("短文本不应截断: %s", short)
	}
	long := truncatePreflightText(string(make([]byte, preflightMaxIssueTextLen+100)))
	// 截断后正文 ≤ 上限，结尾仅可能追加省略号（多字节，放 4 字节余量）。
	if len(long) > preflightMaxIssueTextLen+4 {
		t.Fatalf("长文本未截断: %d", len(long))
	}
}
