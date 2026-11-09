package main

import (
	"strings"
	"testing"
)

// TestIsAllowedMavenLibURL_Trusted 官方与镜像 Maven 主机必须放行（重写前后都可能出现）。
func TestIsAllowedMavenLibURL_Trusted(t *testing.T) {
	good := []string{
		"https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1/forge-1.20.1.jar",
		"https://maven.neoforged.net/releases/net/neoforged/neoforge/21.0.0/neoforge-21.0.0.jar",
		"https://libraries.minecraft.net/com/mojang/logging/1.0.0/logging-1.0.0.jar",
		"https://piston-data.mojang.com/v1/objects/abc/client.jar",
		"https://maven.fabricmc.net/net/fabricmc/fabric-loader/0.15.0/fabric-loader-0.15.0.jar",
		"https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar",
		"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/a.jar",
	}
	for _, u := range good {
		if !isAllowedMavenLibURL(u) {
			t.Errorf("可信 Maven URL 被误拒: %s", u)
		}
	}
}

// TestIsAllowedMavenLibURL_Malicious 攻击者可控主机/协议必须全部拒绝。
func TestIsAllowedMavenLibURL_Malicious(t *testing.T) {
	bad := []string{
		"http://maven.minecraftforge.net/x.jar",                              // 非 https
		"https://evil.example/x.jar",                                         // 不在白名单
		"https://maven.minecraftforge.net.evil.com/x.jar",                    // 后缀伪造子域
		"https://evilmaven.minecraftforge.net/x.jar",                         // 伪造子域（精确匹配拦截）
		"https://user:pass@bmclapi2.bangbang93.com/x.jar",                    // userinfo
		"https://bmclapi2.bangbang93.com:8443/x.jar",                         // 非标准端口
		"https://bmclapi2.bangbang93.com@evil.com/x.jar",                     // 视觉混淆
		"javascript:alert(1)",                                                // 非 http(s)
		"",                                                                   // 空
		"https://repo1.maven.org.evil.tld/x.jar",                             // 结尾前接伪域
		"   ",                                                                // 纯空白
	}
	for _, u := range bad {
		if isAllowedMavenLibURL(u) {
			t.Errorf("危险 Maven URL 必须被拒绝，但被放行: %q", u)
		}
	}
}

// TestIsAllowedMavenLibURL_TrailingDot 结尾点的主机名规范化后仍须精确命中。
func TestIsAllowedMavenLibURL_TrailingDot(t *testing.T) {
	if !isAllowedMavenLibURL("https://repo1.maven.org./maven2/x/y.jar") {
		t.Error("合法的结尾点主机名应被规范化后放行")
	}
	if isAllowedMavenLibURL("https://evil.com./x.jar") {
		t.Error("非白名单主机即使带结尾点也必须拒绝")
	}
}

// TestIsSafeRelPath 锁定安装器内相对路径的 Zip Slip 判定（跨平台一致的遍历用例）。
func TestIsSafeRelPath(t *testing.T) {
	if got := isSafeRelPath("net/minecraftforge/forge/a.jar"); got != "net/minecraftforge/forge/a.jar" {
		t.Errorf("正常 maven 路径被误判: %q", got)
	}
	if got := isSafeRelPath("./a.jar"); got != "a.jar" {
		t.Errorf("./ 前缀应被 Clean: %q", got)
	}
	bad := []string{
		"",
		"../evil.jar",
		"a/../../evil.jar",
		"a/b/../../../etc/passwd",
		"mods/../../../windows/system32",
	}
	for _, in := range bad {
		if got := isSafeRelPath(in); got != "" {
			t.Errorf("危险相对路径 %q 必须返回空串，got %q", in, got)
		}
	}
}

// toBMCLMirror 复刻 downloadFabricLibraries 里的官方→BMCLAPI 镜像替换，
// 用来锁定“替换前的源主机”和“替换后的镜像主机”都必须在信任白名单内。
func toBMCLMirror(u string) string {
	u = strings.Replace(u, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
	u = strings.Replace(u, "https://repo1.maven.org/maven2/", "https://bmclapi2.bangbang93.com/maven/", 1)
	u = strings.Replace(u, "https://libraries.minecraft.net/", "https://bmclapi2.bangbang93.com/libraries/", 1)
	return u
}

// TestFabricLibrarySourcesAndMirrorsTrusted Fabric profile 里出现的官方库主机，
// 以及镜像替换后的实际下载地址，都必须通过主机白名单；否则要么误拒合法库，
// 要么（更危险）把下载导向了非信任主机。
func TestFabricLibrarySourcesAndMirrorsTrusted(t *testing.T) {
	sources := []string{
		"https://maven.fabricmc.net/net/fabricmc/fabric-loader/0.16.0/fabric-loader-0.16.0.jar",
		"https://repo1.maven.org/maven2/org/ow2/asm/asm-commons/9.7/asm-commons-9.7.jar",
		"https://libraries.minecraft.net/com/mojang/blocklist/1.0.10/blocklist-1.0.10.txt",
	}
	for _, src := range sources {
		if !isAllowedMavenLibURL(src) {
			t.Errorf("Fabric 官方源主机应在白名单内: %s", src)
		}
		mirrored := toBMCLMirror(src)
		if !isAllowedMavenLibURL(mirrored) {
			t.Errorf("镜像替换后的地址也应在白名单内: %s (源 %s)", mirrored, src)
		}
	}
}

// TestFabricTamperedLibraryRejected 即使伪造的 Fabric 库 URL 也带 .jar、
// 长得像合法路径，只要主机不在白名单就必须被挡下（结合 sha1 锚点双保险）。
func TestFabricTamperedLibraryRejected(t *testing.T) {
	attacks := []string{
		"https://maven.fabricmc.net.evil.tld/net/fabricmc/fabric-loader/0.16.0/fabric-loader-0.16.0.jar",
		"https://fabricmc.net.s3.evil.example/loader.jar",
		"https://repo1.maven.org@127.0.0.1/maven2/x.jar",
		"http://libraries.minecraft.net/com/mojang/x.jar",
	}
	for _, u := range attacks {
		if isAllowedMavenLibURL(u) {
			t.Errorf("被篡改的 Fabric 库 URL 必须被拒绝: %s", u)
		}
	}
}
