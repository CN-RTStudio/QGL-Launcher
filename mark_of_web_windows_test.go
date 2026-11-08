//go:build windows

package main

// mark_of_web_windows_test.go 只在 Windows 上编译：真实写入并读回
// Zone.Identifier 备用数据流，验证 MOTW 的端到端行为。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyMOTWWindowsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "installer.msi")
	if err := os.WriteFile(target, []byte("MZ fake installer"), 0o600); err != nil {
		t.Fatalf("建安装包占位文件失败: %v", err)
	}

	applied, err := applyMarkOfTheWebWithReferrer(target,
		"https://dl.example/jre.msi", "https://mirror.example/")
	if err != nil {
		t.Fatalf("写 MOTW 失败: %v", err)
	}
	if !applied {
		t.Fatal("Windows 上应返回 applied=true")
	}

	got, err := readMarkOfTheWeb(target)
	if err != nil {
		t.Fatalf("读回 MOTW 失败: %v", err)
	}
	for _, want := range []string{
		"[ZoneTransfer]",
		"ZoneId=3",
		"HostUrl=https://dl.example/jre.msi",
		"ReferrerUrl=https://mirror.example/",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ADS 内容缺少 %q，实际:\n%s", want, got)
		}
	}

	// 主文件内容不应被 MOTW 写入影响。
	main, err := os.ReadFile(target)
	if err != nil || string(main) != "MZ fake installer" {
		t.Fatalf("主文件内容被破坏: %q err=%v", main, err)
	}

	// 重复写应覆盖而不是追加。
	if _, err := applyMarkOfTheWeb(target, "https://dl.example/second.exe"); err != nil {
		t.Fatalf("二次写 MOTW 失败: %v", err)
	}
	got2, _ := readMarkOfTheWeb(target)
	if strings.Count(got2, "[ZoneTransfer]") != 1 {
		t.Fatalf("重复写应只保留一个段，实际:\n%s", got2)
	}
	if !strings.Contains(got2, "second.exe") {
		t.Fatal("二次写应更新 HostUrl")
	}
}

func TestApplyMOTWWindowsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(real, []byte("data"), 0o600); err != nil {
		t.Fatalf("建真实文件失败: %v", err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("当前环境无权创建符号链接，跳过")
	}
	if applied, err := applyMarkOfTheWeb(link, "https://x.test/f"); err == nil || applied {
		t.Fatalf("符号链接目标必须被拒绝，得到 applied=%v err=%v", applied, err)
	}
}
