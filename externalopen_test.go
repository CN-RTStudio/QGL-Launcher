package main

import (
	"net"
	"testing"
)

func TestValidateBrowserURLAcceptsNormalHTTPS(t *testing.T) {
	good := []string{
		"https://adoptium.net/temurin/releases/",
		"https://www.oracle.com/java/technologies/downloads/",
		"https://aka.ms/download-jdk/microsoft-jdk-17-windows-x64.msi",
		"  https://docs.azul.com/core/zulu-openjava/  ",
		"https://corretto.aws/downloads/latest",
	}
	for _, in := range good {
		if _, err := ValidateBrowserURL(in); err != nil {
			t.Fatalf("应放行正常厂商下载页 %q，却被拒: %v", in, err)
		}
	}
}

func TestValidateBrowserURLRejectsScheme(t *testing.T) {
	bad := []string{
		"", "   ", "http://adoptium.net/", "ftp://adoptium.net/x",
		"file:///C:/Windows/System32/calc.exe", "javascript:alert(1)",
		"data:text/html,x", "//adoptium.net/", "adoptium.net/",
		"HTTPS\n://adoptium.net", "https://adoptium.net/\r\nfile:///x",
		"https://adoptium.net/\x00evil",
	}
	for _, in := range bad {
		if _, err := ValidateBrowserURL(in); err == nil {
			t.Fatalf("应拒绝危险/畸形 URL %q", in)
		}
	}
}

func TestValidateBrowserURLRejectsUserinfo(t *testing.T) {
	bad := []string{
		"https://www.oracle.com@evil.test/download",
		"https://user:pass@adoptium.net/",
		"https://adoptium.net@127.0.0.1/",
	}
	for _, in := range bad {
		_, err := ValidateBrowserURL(in)
		if err == nil {
			t.Fatalf("应拒绝带 userinfo 的混淆链接 %q", in)
		}
		if be, ok := err.(*BrowserURLError); ok && be.Code != "browser-url-userinfo" {
			// userinfo 串也可能在内网 IP 处被拦，只要被拒即可；这里仅记录非预期 code。
			t.Logf("%q 被 %s 拦截（可接受）", in, be.Code)
		}
	}
}

func TestValidateBrowserURLRejectsInternalAndIP(t *testing.T) {
	bad := []string{
		"https://127.0.0.1/",
		"https://127.0.0.1:8443/x",
		"https://localhost/",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.5/",
		"https://192.168.1.10/admin",
		"https://172.16.0.9/",
		"https://[::1]/",
		"https://[fe80::1]/",
		"https://8.8.8.8/", // 裸公网 IP 也拒绝（反钓鱼）
		"https://0.0.0.0/",
	}
	for _, in := range bad {
		if _, err := ValidateBrowserURL(in); err == nil {
			t.Fatalf("应拒绝内网/本机/裸 IP 链接 %q", in)
		}
	}
}

func TestValidateBrowserURLRejectsBadPortAndDomain(t *testing.T) {
	bad := []string{
		"https://adoptium.net:8080/x",
		"https://adoptium.net:4443/",
		"https://tool/x",            // 无点
		"https://adoptium.c/",       // TLD 太短
		"https://-bad.example.com/", // 标签前导连字符
		"https://bad-.example.com/", // 标签结尾连字符
		"https://exa mple.com/",     // 空格主机
	}
	for _, in := range bad {
		if _, err := ValidateBrowserURL(in); err == nil {
			t.Fatalf("应拒绝端口/域名异常链接 %q", in)
		}
	}
}

func TestValidateBrowserURLTrimsButKeepsPath(t *testing.T) {
	clean, err := ValidateBrowserURL("   https://adoptium.net/temurin/releases/?version=17  ")
	if err != nil {
		t.Fatalf("意外被拒: %v", err)
	}
	if clean != "https://adoptium.net/temurin/releases/?version=17" {
		t.Fatalf("规范化结果不正确: %q", clean)
	}
}

func TestIsPrivateOrLocalIP(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.1.2.3", "192.168.0.1", "172.20.0.4", "169.254.1.1",
		"100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
	}
	for _, s := range private {
		if !isPrivateOrLocalIP(net.ParseIP(s)) {
			t.Fatalf("应判定为内网/本机: %s", s)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "142.250.80.46", "2606:4700:4700::1111"}
	for _, s := range public {
		if isPrivateOrLocalIP(net.ParseIP(s)) {
			t.Fatalf("不应误判公网地址为内网: %s", s)
		}
	}
	if isPrivateOrLocalIP(nil) != true {
		t.Fatal("nil IP 应按不可信处理")
	}
}

func TestBrowserOpenCommandBuildsNoShell(t *testing.T) {
	cmd, err := BrowserOpenCommand("https://adoptium.net/x")
	if err != nil {
		t.Fatalf("构造命令失败: %v", err)
	}
	if len(cmd.Args) < 2 {
		t.Fatal("命令参数为空")
	}
	// URL 必须作为独立 argv 元素存在，而不是拼接进 shell 字符串。
	found := false
	for _, a := range cmd.Args {
		if a == "https://adoptium.net/x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("URL 未作为独立参数: %v", cmd.Args)
	}
}

func TestBrowserOpenCommandRejectsBeforeBuild(t *testing.T) {
	if _, err := BrowserOpenCommand("file:///C:/Windows/System32/calc.exe"); err == nil {
		t.Fatal("危险 URL 不应构造出打开命令")
	}
	if _, err := BrowserOpenCommand("javascript:alert(1)"); err == nil {
		t.Fatal("javascript: 不应构造出打开命令")
	}
}

func TestValidateBrowserURLRejectsObfuscatedIPLiteral(t *testing.T) {
	// inet_aton 短格式 / 单整数 / 进制混淆必须被显式判成 IP 字面量拒绝，
	// 不能再只靠后面域名校验的"TLD 太短 / 单段无点"巧合兜底。
	bad := []string{
		"https://127.1/",      // 短格式 127.0.0.1
		"https://2130706433/", // 单整数 127.0.0.1
		"https://0x7f000001/", // 十六进制 127.0.0.1
		"https://0177.0.0.1/", // 八进制 127.0.0.1
		"https://149.154.1/",  // 短格式公网，也按裸 IP 拒绝
		"https://0x0a010203/", // 单整数 10.1.2.3 内网
		"https://0x0a64401/",  // 0.10.100.1 之类畸形
	}
	for _, in := range bad {
		if _, err := ValidateBrowserURL(in); err == nil {
			t.Fatalf("混淆 IP 字面量应被拒绝 %q", in)
		}
	}
}

func TestIPLiteralFromHostRecognizesObfuscated(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.1", true},
		{"2130706433", true},
		{"0x7f000001", true},
		{"0177.0.0.1", true},
		{"[::1]", true},
		{"::1", true},
		{"example.com", false},
		{"", false},
	}
	for _, c := range cases {
		if _, ok := ipLiteralFromHost(c.host); ok != c.want {
			t.Fatalf("ipLiteralFromHost(%q)=%v want %v", c.host, ok, c.want)
		}
	}
}
