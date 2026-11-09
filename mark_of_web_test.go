package main

// mark_of_web_test.go 覆盖 Mark of the Web 模块的平台无关逻辑：
// ADS 文本构造、URL 注入清洗、目标文件状态校验，以及非 Windows 平台
// 必须安静地 no-op（保证跨平台编译行为）。
// Windows 真实 ADS 读写在 mark_of_web_windows_test.go。

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSanitizeZoneURL(t *testing.T) {
	if _, err := sanitizeZoneURL("https://x.test/a\r\nHostUrl=evil"); err == nil {
		t.Fatal("含 CRLF 的 URL 必须被拒绝")
	}
	long := strings.Repeat("a", motwMaxURLLength+1)
	if _, err := sanitizeZoneURL(long); err == nil {
		t.Fatal("超长 URL 必须被拒绝")
	}
	got, err := sanitizeZoneURL("  https://x.test  ")
	if err != nil || got != "https://x.test" {
		t.Fatalf("合法 URL 应被 trim 后接受，得到 %q err=%v", got, err)
	}
	if got, err := sanitizeZoneURL("   "); err != nil || got != "" {
		t.Fatalf("空白 URL 应归一为空串，得到 %q err=%v", got, err)
	}
}

func TestBuildZoneIdentifierBody(t *testing.T) {
	body, err := buildZoneIdentifierBody("https://dl.test/jre.msi", "https://page.test/")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	for _, want := range []string{
		"[ZoneTransfer]\r\n",
		"ZoneId=3\r\n",
		"ReferrerUrl=https://page.test/\r\n",
		"HostUrl=https://dl.test/jre.msi\r\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("MOTW 正文缺少 %q，实际:\n%s", want, body)
		}
	}

	// 无 referrer 时不应写出该键。
	body2, err := buildZoneIdentifierBody("https://dl.test/jre.msi", "")
	if err != nil {
		t.Fatalf("无 referrer 构造失败: %v", err)
	}
	if strings.Contains(body2, "ReferrerUrl=") {
		t.Errorf("空 referrer 不应写 ReferrerUrl:\n%s", body2)
	}

	// 注入尝试必须被挡在数据流之外。
	if _, err := buildZoneIdentifierBody("https://x.test/\r\nZoneId=0", ""); err == nil {
		t.Fatal("HostUrl 中的换行注入必须被拒绝")
	}
}

func TestFileSupportsADS(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("建普通文件失败: %v", err)
	}
	if err := fileSupportsADS(regular); err != nil {
		t.Errorf("普通文件应通过校验: %v", err)
	}
	if err := fileSupportsADS(filepath.Join(dir, "missing")); err == nil {
		t.Error("不存在的文件应报错")
	}
}

func TestApplyMOTWNonWindowsNoOp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 行为由 windows 专用测试覆盖")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("建文件失败: %v", err)
	}
	applied, err := applyMarkOfTheWeb(p, "https://x.test/f")
	if err != nil || applied {
		t.Fatalf("非 Windows 必须 (false,nil)，得到 applied=%v err=%v", applied, err)
	}
	if _, err := readMarkOfTheWeb(p); err != errMarkOfTheWebUnsupported {
		t.Fatalf("非 Windows 读 MOTW 应返回 errMarkOfTheWebUnsupported，得到 %v", err)
	}
}
