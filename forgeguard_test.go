package main

import (
	"strings"
	"testing"
)

func TestValidateForgeVersionString(t *testing.T) {
	var lim0 ForgeLimits
	lim := lim0.withDefaults()

	valid := []string{
		"47.1.0",
		"1.20.1-forge-47.1.0",
		"47.1.0-1.20.1",
		"20.4.80-beta",
		"1.20.1-neoforge-20.4.80",
		"47.10.0",
	}
	for _, v := range valid {
		got, err := ValidateForgeVersionString(v, lim)
		if err != nil {
			t.Fatalf("valid %q rejected: %v", v, err)
		}
		if got == "" {
			t.Fatalf("valid %q produced empty normalized version", v)
		}
	}

	invalid := []string{
		"",
		"  ",
		"../../etc/passwd",
		"47.1.0\n",
		"latest",
		"recommended",
		"47..1",
		"-forge",
		"for",
		"47.1.0;rm -rf /",
		"<script>alert(1)</script>",
	}
	for _, v := range invalid {
		if _, err := ValidateForgeVersionString(v, lim); err == nil {
			t.Fatalf("invalid %q accepted", v)
		}
	}
}

func TestCompareForgeVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"47.1.0", "47.1.0", 0},
		{"47.1.0", "47.1.1", -1},
		{"47.1.1", "47.1.0", 1},
		{"47.10.0", "47.9.0", 1}, // 字典序陷阱：前缀 "47.1" 会误判小
		{"47.1.0", "47.1.0-rc1", 1},
		{"47.1.0-rc1", "47.1.0", -1},
		{"47.1.0-beta2", "47.1.0-beta10", -1},
		{"47.1.0-rc1", "47.1.0-beta9", 1},
		{"47.1.0", "47.1.0.0", 0},
	}
	for _, c := range cases {
		got := CompareForgeVersions(c.a, c.b)
		if got != c.want {
			t.Fatalf("CompareForgeVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestValidateForgeDownloadURL(t *testing.T) {
	var lim0 ForgeLimits
	lim := lim0.withDefaults()

	valid := []string{
		"https://files.minecraftforge.net/maven/net/minecraftforge/forge/1.20.1-47.1.0/forge-1.20.1-47.1.0-installer.jar",
		"https://maven.neoforged.net/releases/net/neoforged/forge/20.4.80-beta/forge-20.4.80-beta-installer.jar",
		"https://raw.githubusercontent.com/MinecraftForge/MinecraftForge/1.20.1/build.gradle",
	}
	for _, u := range valid {
		got, err := ValidateForgeDownloadURL(u, lim)
		if err != nil {
			t.Fatalf("valid url %q rejected: %v", u, err)
		}
		if got == "" {
			t.Fatalf("valid url %q produced empty result", u)
		}
	}

	invalid := []string{
		"http://files.minecraftforge.net/forge.jar",                                   // 非 https
		"https://evil.example.com/forge.jar",                                          // 非白名单 host
		"https://files.minecraftforge.net.evil.com/forge.jar",                         // 子域伪装（后缀不匹配）
		"https://192.168.1.1/forge.jar",                                               // IP 直连
		"https://user:pass@files.minecraftforge.net/forge.jar",                        // userinfo
		"https://files.minecraftforge.net/" + string(rune(0x01)) + "x.jar",            // 控制字符
		"https://files.minecraftforge.net/" + strings.Repeat("a", 300) + "/forge.jar", // 超长段
	}
	for _, u := range invalid {
		if _, err := ValidateForgeDownloadURL(u, lim); err == nil {
			t.Fatalf("invalid url %q accepted", u)
		}
	}
}

func TestSplitSuffix(t *testing.T) {
	name, num := splitSuffix("beta3")
	if name != "beta" || num != 3 {
		t.Fatalf("splitSuffix(beta3)=%q,%d want beta,3", name, num)
	}
	name, num = splitSuffix("rc")
	if name != "rc" || num != 0 {
		t.Fatalf("splitSuffix(rc)=%q,%d want rc,0", name, num)
	}
}

func TestIsIPLiteralHostReuse(t *testing.T) {
	if !isIPLiteralHost("192.168.1.1") {
		t.Fatal("IPv4 not detected")
	}
	if !isIPLiteralHost("127.0.0.1") {
		t.Fatal("loopback not detected")
	}
	if isIPLiteralHost("files.minecraftforge.net") {
		t.Fatal("hostname mistaken as IP")
	}
	if !isIPLiteralHost("2001:db8::1") {
		t.Fatal("IPv6 not detected")
	}
	// inet_aton 混淆写法也必须被识别为 IP 字面量，否则更新源/Forge/服务器列表
	// 的"拒绝裸 IP"门会把它们误当域名放行。
	for _, h := range []string{"127.1", "2130706433", "0x7f000001", "0177.0.0.1"} {
		if !isIPLiteralHost(h) {
			t.Fatalf("obfuscated IP literal %q not detected", h)
		}
	}
}

func TestSummarizeForgeVerdict(t *testing.T) {
	ok := SummarizeForgeVerdict(ForgeVerdict{NormalizedVersion: "47.1.0", DownloadURL: "https://files.minecraftforge.net/x.jar", OK: true})
	if ok[:14] != "forge install ok" {
		t.Fatalf("unexpected ok summary: %q", ok)
	}
	bad := SummarizeForgeVerdict(ForgeVerdict{OK: false, Reason: "host not allowed"})
	if bad != "forge install rejected reason=host not allowed" {
		t.Fatalf("unexpected bad summary: %q", bad)
	}
}
