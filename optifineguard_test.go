package main

// optifineguard_test.go —— OptiFine 地址/文件名校验内核的测试。

import (
	"strings"
	"testing"
)

func TestValidateOptifineUrl(t *testing.T) {
	var lim0 OptiFineLimits
	lim := lim0.withDefaults()
	good := []string{
		"https://optifine.net/downloads/HD_U_J6.jar",
		"https://download.optifine.net/adloads/OptiFine_1.19.4.jar",
		"https://optifine.cn/adloads/OptiFine_1.20.jar",
		"https://mcimg.net/img/optifine.png",
	}
	bad := []string{
		"",
		"http://optifine.net/x.jar",          // 明文
		"https://evil.com/x.jar",              // 非白名单
		"https://optifine.net.evil.com/x.jar", // 后缀欺骗
		"https://optifine.net\x00x.jar",       // 控制字符
		strings.Repeat("https://optifine.net/"+"a", 300), // 超长
	}
	for _, u := range good {
		if _, err := ValidateOptifineUrl(u, lim); err != nil {
			t.Errorf("url %q rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := ValidateOptifineUrl(u, lim); err == nil {
			t.Errorf("url %q accepted", u)
		}
	}
}

func TestValidateOptifineFileName(t *testing.T) {
	var lim0 OptiFineLimits
	lim := lim0.withDefaults()
	good := []string{
		"OptiFine_1.19.4_HD_U_I3.jar",
		"OptiFine_1.20.1_HD_U_H8.jar",
		"preview_OptiFine_1.21.jar",
		"OptiFine.jar",
	}
	bad := []string{
		"",
		"   ",
		"OptiFine_1.19.4.zip",     // 伪装扩展名
		"OptiFine_1.19.4.exe",     // 伪装扩展名
		"OptiFine_1.19.4.scr",     // 伪装扩展名
		"../OptiFine.jar",          // 路径穿越
		"sub/OptiFine.jar",         // 子目录
		"OptiFine\x00.jar",         // 控制字符
		strings.Repeat("a", 300) + ".jar", // 超长
		".jar",
		"OptiFine.JAR.exe",         // 双重扩展
	}
	for _, n := range good {
		if _, err := ValidateOptifineFileName(n, lim); err != nil {
			t.Errorf("name %q rejected: %v", n, err)
		}
	}
	for _, n := range bad {
		if _, err := ValidateOptifineFileName(n, lim); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

func TestClassifyOptifineUrl(t *testing.T) {
	if ClassifyOptifineUrl("") != "optifine-url-empty" {
		t.Error("empty classification wrong")
	}
	if ClassifyOptifineUrl("http://optifine.net/x") != "optifine-url-non-https" {
		t.Error("non-https classification wrong")
	}
	if ClassifyOptifineUrl("https://optifine.net") != "optifine-url-no-path" {
		t.Error("no-path classification wrong")
	}
	if ClassifyOptifineUrl("https://optifine.net/x.jar") != "optifine-url-ok" {
		t.Error("ok classification wrong")
	}
}

func TestValidateOptifineUrlAuthority(t *testing.T) {
	lim := OptiFineLimits{}
	if _, err := ValidateOptifineUrl("https://optifine.net:443/adloads/x.jar", lim); err != nil {
		t.Fatalf("显式 443 端口应放行: %v", err)
	}
	if _, err := ValidateOptifineUrl("https://optifine.net./x.jar", lim); err != nil {
		t.Fatalf("主机末尾点应归一后放行: %v", err)
	}
	if _, err := ValidateOptifineUrl("https://user@optifine.net/x.jar", lim); err == nil {
		t.Fatal("带 userinfo 的地址应被拒")
	}
	if _, err := ValidateOptifineUrl("https://optifine.net@evil.com/x.jar", lim); err == nil {
		t.Fatal("userinfo 混淆到外部主机的地址应被拒")
	}
	if _, err := ValidateOptifineUrl("https://optifine.net:8443/x.jar", lim); err != nil {
		t.Fatalf("白名单主机非默认端口按主机判定放行: %v", err)
	}
}

func TestSummarizeOptifineError(t *testing.T) {
	if s := SummarizeOptifineError(nil); s != "optifine check ok" {
		t.Errorf("unexpected ok summary: %s", s)
	}
	if s := SummarizeOptifineError(errOptifine("bad")); !strings.Contains(s, "rejected") {
		t.Errorf("unexpected err summary: %s", s)
	}
}

type errOptifine string

func (e errOptifine) Error() string { return string(e) }
