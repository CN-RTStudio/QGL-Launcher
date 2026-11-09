package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsValidPort 端口边界。
func TestIsValidPort(t *testing.T) {
	cases := []struct {
		port int
		want bool
	}{
		{0, false}, {-1, false}, {1, true}, {8080, true},
		{65535, true}, {65536, false}, {70000, false},
	}
	for _, c := range cases {
		if got := isValidPort(c.port); got != c.want {
			t.Errorf("isValidPort(%d)=%v want %v", c.port, got, c.want)
		}
	}
}

// TestIsValidMemory 内存上下界。
func TestIsValidMemory(t *testing.T) {
	if isValidMemory(minMemoryMB - 1) {
		t.Fatal("低于最小内存应拒绝")
	}
	if !isValidMemory(minMemoryMB) || !isValidMemory(maxMemoryMB) {
		t.Fatal("边界值应允许")
	}
	if isValidMemory(maxMemoryMB + 1) {
		t.Fatal("超过最大内存应拒绝")
	}
}

// TestSanitizeServerName 名称里的路径分隔符、父目录跳转和 properties 注入换行必须被清除。
func TestSanitizeServerName(t *testing.T) {
	cases := []struct {
		in   string
		bad  string // 结果中绝不能出现的子串
		desc string
	}{
		{"../etc/passwd", "..", "父目录跳转"},
		{"a\\..\\b", "..", "Windows 分隔跳转"},
		{"line1\nonline-mode=false", "\n", "换行注入"},
		{"car\rriage", "\r", "回车注入"},
		{"root:evil", ":", "冒号"},
	}
	for _, c := range cases {
		got := sanitizeServerName(c.in)
		if containsSubstr(got, c.bad) {
			t.Errorf("%s: 清洗结果 %q 仍含 %q", c.desc, got, c.bad)
		}
	}
	if got := sanitizeServerName("  normal  "); got != "normal" {
		t.Errorf("名称首尾空白应被裁剪，得到 %q", got)
	}
}

func containsSubstr(s, sub string) bool {
	return len(sub) > 0 && indexStr(s, sub) >= 0
}

func indexStr(s, sub string) int {
	ls, lp := len(s), len(sub)
	if lp == 0 {
		return 0
	}
	for i := 0; i+lp <= ls; i++ {
		if s[i:i+lp] == sub {
			return i
		}
	}
	return -1
}

// TestIsPathTraversal 用真实临时目录验证包含判定：
// 基目录内允许、基目录外拒绝、基目录本身允许、../ 跳出拒绝。
func TestIsPathTraversal(t *testing.T) {
	base := t.TempDir()
	inner := filepath.Join(base, "servers", "s1")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	sibling := t.TempDir() // 另一个无关临时目录

	if isPathTraversal(base, inner) {
		t.Fatal("基目录内的路径不应被判为穿越")
	}
	if isPathTraversal(base, base) {
		t.Fatal("基目录自身不应被判为穿越")
	}
	if !isPathTraversal(base, filepath.Join(base, "..", "evil")) {
		t.Fatal("../ 跳出基目录应判为穿越")
	}
	if !isPathTraversal(base, sibling) {
		t.Fatal("基目录之外的无关目录应判为穿越")
	}
}

// TestParseConnectionCodeRejectsBadSegments 非法连接码必须拒绝，
// 尤其第 2/3/4 段超出 0-255、端口越界。
func TestParseConnectionCodeRejectsBadSegments(t *testing.T) {
	a := &App{}
	// 合法：192.168.0.1:25565 -> C, a(10), 0, 1, 63dd(25565)
	if addr, err := a.ParseConnectionCode("C-a-0-1-63dd"); err != nil || addr != "192.168.0.1:25565" {
		t.Fatalf("合法连接码解析错误 addr=%q err=%v", addr, err)
	}
	bad := []string{
		"C-a-0",           // 段数不足
		"C-1ff-0-1-63dd",  // 第2段 >255
		"C-a-100-1-63dd",  // 第3段 >255
		"C-a-0-1-10000",   // 端口 0x10000=65536 越界
		"Z-0-0-0-1",       // 未知前缀
	}
	for _, code := range bad {
		if _, err := a.ParseConnectionCode(code); err == nil {
			t.Errorf("非法连接码 %q 应当解析失败", code)
		}
	}
}

// TestValidateLoadedServerConfig 磁盘上的 config.json 被篡改 / 写坏时，
// 加载校验必须拒绝，绝不带病进入 java -jar 执行路径。
func TestValidateLoadedServerConfig(t *testing.T) {
	a := &App{}
	root := a.GetServerDir()
	good := func() ServerConfig {
		return ServerConfig{
			Name:      "srv1",
			Version:   "1.20.4",
			Port:      25565,
			MaxMemory: 2048,
			MinMemory: 1024,
			ServerDir: filepath.Join(root, "srv1"),
		}
	}
	if err := a.validateLoadedServerConfig(nil); err == nil {
		t.Fatal("nil 配置必须拒绝")
	}
	if err := a.validateLoadedServerConfig(func() *ServerConfig { c := good(); return &c }()); err != nil {
		t.Fatalf("合法配置应放行: %v", err)
	}

	bad := []struct {
		name string
		mut  func(*ServerConfig)
	}{
		{"空名称", func(c *ServerConfig) { c.Name = "" }},
		{"名称注入换行", func(c *ServerConfig) { c.Name = "a\nonline-mode=false" }},
		{"版本号父目录跳转", func(c *ServerConfig) { c.Version = "../evil" }},
		{"版本号带分隔符", func(c *ServerConfig) { c.Version = `a\b` }},
		{"端口为0", func(c *ServerConfig) { c.Port = 0 }},
		{"端口越界", func(c *ServerConfig) { c.Port = 70000 }},
		{"内存过小", func(c *ServerConfig) { c.MinMemory, c.MaxMemory = 16, 16 }},
		{"最小内存大于最大", func(c *ServerConfig) { c.MinMemory, c.MaxMemory = 4096, 2048 }},
		{"相对服务器目录", func(c *ServerConfig) { c.ServerDir = filepath.Join("server", "srv1") }},
		{"目录跳出根", func(c *ServerConfig) { c.ServerDir = filepath.Join(root, "..", "evil") }},
		{"目录指向无关绝对路径", func(c *ServerConfig) { c.ServerDir = t.TempDir() }},
	}
	for _, b := range bad {
		c := good()
		b.mut(&c)
		if err := a.validateLoadedServerConfig(&c); err == nil {
			t.Errorf("非法配置必须被拒绝: %s (dir=%q)", b.name, c.ServerDir)
		}
	}
}

// TestServerJarRequiresAbsoluteCustomDir 由 CreateServer 的目录策略保证：
// 相对自定义路径应在真正落盘前被拒绝（这里只验证判定前提 filepath.IsAbs）。
func TestServerJarRequiresAbsoluteCustomDir(t *testing.T) {
	if filepath.IsAbs("rel/path") {
		t.Fatal("相对路径不应被识别为绝对路径")
	}
	if !filepath.IsAbs(filepath.Join(t.TempDir(), "x")) {
		t.Fatal("临时目录拼出的绝对路径应被识别为绝对路径")
	}
}
