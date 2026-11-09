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

// 即便调用方完全不传 valueValidator（nil），键名与单行值底线也必须生效，防止借
// value 注入新配置行。
