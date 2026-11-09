package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateServerPropertyRejectsEmptyKey(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "server.properties")
	_ = os.WriteFile(fp, []byte("a=b\n"), 0o600)
	if err := updateServerProperty(fp, "  ", "v", nil); err == nil {
		t.Fatal("空键应被拒绝")
	}
}

func TestValidatePropertyKey(t *testing.T) {
	good := []string{"server-port", "level-name", "a.b_c", "MOTD1", "x-y.z"}
	for _, k := range good {
		if err := validatePropertyKey(k); err != nil {
			t.Fatalf("合法键 %q 应放行: %v", k, err)
		}
	}
	bad := []string{"", "a=b", "c:d", "a b", "x\ny", "p\tq", string([]byte{'k', 0x00})}
	for _, k := range bad {
		if err := validatePropertyKey(k); err == nil {
			t.Fatalf("非法键 %q 应被拒绝", k)
		}
	}
}

func TestValidatePropertyValueSingleLine(t *testing.T) {
	for _, v := range []string{"25565", "true", "A Server", "hello world"} {
		if err := validatePropertyValueSingleLine(v); err != nil {
			t.Fatalf("正常值 %q 应放行: %v", v, err)
		}
	}
	for _, v := range []string{"a\nb", "a\rb", "a\r\nb", string([]byte{'a', 0x00}), "x\x1by"} {
		if err := validatePropertyValueSingleLine(v); err == nil {
			t.Fatalf("含换行/控制字符的值 %q 应被拒绝", v)
		}
	}
}

func TestUpdateServerPropertyRejectsInjectionWithoutValidator(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "server.properties")
	original := "online-mode=true\nserver-port=25565\n"
	if err := os.WriteFile(fp, []byte(original), 0o600); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	before, _ := os.ReadFile(fp)

	inject := "false\nwhite-list=false"
	if err := updateServerProperty(fp, "motd", inject, nil); err == nil {
		t.Fatal("含换行的注入值必须被拒绝（即使 validator 为 nil）")
	}
	if err := updateServerProperty(fp, "bad key", "v", nil); err == nil {
		t.Fatal("含空格的非法键必须被拒绝")
	}
	if err := updateServerProperty(fp, "a=b", "v", nil); err == nil {
		t.Fatal("含分隔符的非法键必须被拒绝")
	}
	after, _ := os.ReadFile(fp)
	if string(after) != string(before) {
		t.Fatalf("拒绝注入时文件不应被改动\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestValidateServerMotd(t *testing.T) {
	good := []string{"我的服务器", "A nice server", "1.20 生存服"}
	for _, v := range good {
		if err := validateServerMotd(v); err != nil {
			t.Errorf("正常 motd 应通过 %q: %v", v, err)
		}
	}
	bad := []string{
		"",
		"a\nb=white-list=true",
		"line1\rline2",
		"tab\there",
		"nul\x00here",
		strings.Repeat("长", maxServerNameLen+1),
	}
	for _, v := range bad {
		if err := validateServerMotd(v); err == nil {
			t.Errorf("非法 motd 应被拒绝 %q", v)
		}
	}
}

func TestWriteInitialServerProperties(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "server.properties")
	if err := writeInitialServerProperties(fp, 25565, true, "我的 生存服"); err != nil {
		t.Fatalf("创建初始配置失败: %v", err)
	}
	data, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	p := parseServerProperties(data)
	if v, _ := p.Get("server-port"); v != "25565" {
		t.Errorf("server-port 错误: %q", v)
	}
	if v, _ := p.Get("online-mode"); v != "true" {
		t.Errorf("online-mode 错误: %q", v)
	}
	if v, _ := p.Get("motd"); v != "我的 生存服" {
		t.Errorf("motd 错误: %q", v)
	}

	// 非法端口 / 注入型 motd 必须拒绝，且不留半成品文件。
	badPath := filepath.Join(dir, "bad.properties")
	if err := writeInitialServerProperties(badPath, 70000, false, "x"); err == nil {
		t.Error("非法端口应拒绝")
	}
	if err := writeInitialServerProperties(badPath, 25565, false, "x\nenable-command-block=true"); err == nil {
		t.Error("含换行的 motd 应拒绝")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Error("写入失败后不应留下配置或临时文件")
	}
}

func TestSanitizeServerNameHardening(t *testing.T) {
	// 正常中文名 / 含空格名保留。
	if got := sanitizeServerName(" 我的 服务器 "); got != "我的 服务器" {
		t.Errorf("正常名被破坏: %q", got)
	}
	// 控制字节 / 保留设备名 / 尾点 / 超长一律拒绝为空。
	bad := []string{
		"a\x00b", "tab\tname", "esc\x1bx",
		"CON", "nul", "com1", "PRN.txt",
		"trailing.",
		strings.Repeat("名", maxServerNameLen+1),
	}
	for _, v := range bad {
		if got := sanitizeServerName(v); got != "" {
			t.Errorf("非法服务器名应被净化为空，输入 %q 得到 %q", v, got)
		}
	}
}
