package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePropertiesBasic(t *testing.T) {
	in := []byte("# 注释\n! 另一种注释\n\nserver-port=25565\nmax-players:20\r\nbrokenline\n")
	p := parseServerProperties(in)
	if v, ok := p.Get("server-port"); !ok || v != "25565" {
		t.Fatalf("server-port 解析错误 v=%q ok=%v", v, ok)
	}
	if v, ok := p.Get("max-players"); !ok || v != "20" {
		t.Fatalf("冒号分隔解析错误 v=%q ok=%v", v, ok)
	}
	if _, ok := p.Get("brokenline"); ok {
		t.Fatal("无分隔符的行不应被当成键值对")
	}
	if got := len(p.Keys()); got != 2 {
		t.Fatalf("应只有两个键，得到 %d", got)
	}
}

func TestSetPropertiesDedups(t *testing.T) {
	// 重复键：旧逻辑只改第一行，序列化后两行冲突。
	in := []byte("online-mode=true\nonline-mode=false\n")
	p := parseServerProperties(in)
	p.Set("online-mode", "false")
	out := string(p.Marshal())
	if strings.Count(out, "online-mode=") != 1 {
		t.Fatalf("重复键应当只保留一行，得到:\n%s", out)
	}
	if v, _ := p.Get("online-mode"); v != "false" {
		t.Fatalf("值应为 false，得到 %q", v)
	}
}

func TestSetPropertiesAppendsAndPreservesComments(t *testing.T) {
	in := []byte("# head\nserver-port=25565\n")
	p := parseServerProperties(in)
	p.Set("online-mode", "true")
	out := string(p.Marshal())
	if !strings.Contains(out, "# head\n") {
		t.Fatal("注释应被保留")
	}
	if !strings.HasSuffix(out, "online-mode=true\n") {
		t.Fatalf("缺失键应追加到末尾，得到:\n%s", out)
	}
}

func TestSetPropertiesCRLF(t *testing.T) {
	// CRLF 文件里旧逻辑的键名会带 \r 导致 HasPrefix 失配而重复追加。
	in := []byte("online-mode=true\r\nserver-port=25565\r\n")
	p := parseServerProperties(in)
	p.Set("online-mode", "false")
	out := string(p.Marshal())
	if strings.Count(out, "online-mode") != 1 {
		t.Fatalf("CRLF 下应原地更新而非追加，得到:\n%s", out)
	}
	if !strings.Contains(out, "online-mode=false") {
		t.Fatal("应更新为 false")
	}
}

func TestValidateBoolProperty(t *testing.T) {
	for _, good := range []string{"true", "false", " true ", "TRUE", "False"} {
		if err := validateBoolProperty(good); err != nil {
			t.Errorf("%q 应通过校验: %v", good, err)
		}
	}
	for _, bad := range []string{"", "yes", "1", "true\nonline-mode=false", "false\r"} {
		if err := validateBoolProperty(bad); err == nil {
			t.Errorf("%q 应被拒绝", bad)
		}
	}
}

func TestUpdateServerPropertyFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "server.properties")
	original := "# Minecraft server properties\nonline-mode=true\nserver-port=25565\n"
	if err := os.WriteFile(fp, []byte(original), 0o600); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	if err := updateServerProperty(fp, "online-mode", "false", validateBoolProperty); err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	data, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "online-mode=false") || strings.Count(out, "online-mode") != 1 {
		t.Fatalf("落盘内容异常:\n%s", out)
	}
	if !strings.Contains(out, "server-port=25565") || !strings.Contains(out, "# Minecraft server properties") {
		t.Fatal("其它配置与注释应保留")
	}
	// 非法值必须被拒绝且不改动文件。
	before := string(data)
	if err := updateServerProperty(fp, "online-mode", "maybe", validateBoolProperty); err == nil {
		t.Fatal("非法布尔值应报错")
	}
	after, _ := os.ReadFile(fp)
	if string(after) != before {
		t.Fatal("拒绝非法值时不应改动文件")
	}
}

func TestUpdateServerPropertyMissingFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "nope.properties")
	if err := updateServerProperty(fp, "k", "v", nil); err == nil {
		t.Fatal("目标文件不存在时应返回错误")
	}
}

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

// 即便调用方完全不传 valueValidator（nil），键名与单行值底线也必须生效，防止借
// value 注入新配置行。
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
