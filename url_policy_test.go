package main

import "testing"

// TestSafeExternalURL_Allowed 白名单主机上的正常 https 链接必须放行。
func TestSafeExternalURL_Allowed(t *testing.T) {
	good := []string{
		"https://www.minecraft.net/en-us",
		"https://github.com/BKsell/OpenQGL",
		"https://raw.githubusercontent.com/user/repo/main/file.go",
		"https://api.modrinth.com/v2/project/abc",
		"https://cdn.modrinth.com/data/abc/versions/a/x.mrpack",
		"https://www.curseforge.com/minecraft/mc-mods/sodium",
		"https://maven.fabricmc.net/net/fabricmc/fabric-loader/",
		"https://bmclapi2.bangbang93.com/version.json",
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
	}
	for _, u := range good {
		if err := safeExternalURL(u); err != nil {
			t.Errorf("合法外部链接被误拒 %q: %v", u, err)
		}
	}
}

// TestSafeExternalURL_TrimsSpace 首尾空白必须被容忍，避免展示用字符串误判。
func TestSafeExternalURL_TrimsSpace(t *testing.T) {
	if err := safeExternalURL("  https://github.com/x "); err != nil {
		t.Errorf("带空白的合法链接应被 TrimSpace 后放行: %v", err)
	}
}

// TestSafeExternalURL_HostCaseInsensitive 主机名大小写不敏感。
func TestSafeExternalURL_HostCaseInsensitive(t *testing.T) {
	if err := safeExternalURL("https://GITHUB.com/x"); err != nil {
		t.Errorf("大写主机名应被规范化后放行: %v", err)
	}
	if err := safeExternalURL("https://GitHub.Com/X"); err != nil {
		t.Errorf("混合大小写主机名应被规范化后放行: %v", err)
	}
}

// TestSafeExternalURL_Explicit443 显式写 :443 等价于默认端口，应放行。
func TestSafeExternalURL_Explicit443(t *testing.T) {
	if err := safeExternalURL("https://github.com:443/x"); err != nil {
		t.Errorf("显式 443 端口应放行: %v", err)
	}
}

// TestSafeExternalURL_Rejected 危险 / 非法链接必须全部拒绝。
func TestSafeExternalURL_Rejected(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"http://github.com/x",                                          // 非 https
		"https://evil.example/x",                                       // 非白名单主机
		"javascript:alert(1)",                                          // 危险 scheme
		"file:///c:/windows/win.ini",                                   // 本地文件 scheme
		"data:text/html,<script>alert(1)</script>",                     // data scheme
		"vbscript:msgbox(1)",                                           // vbscript
		"ftp://github.com/x",                                           // ftp
		"https://github.com:8443/x",                                    // 非标准端口
		"https://github.com:80/x",                                      // 80 端口
		"https://user:pass@github.com/x",                               // userinfo
		"https://github.com@evil.com/x",                                // @ 视觉混淆
		"https://notgithub.com/x",                                      // 形似但不在名单
		"https://github.com.evil.com/x",                                // 后缀伪造子域
		"https://evilgithub.com/x",                                     // 前缀拼接伪造
		"https://sub.github.com/x",                                     // github.com 而非 github 官方域
		"https://wwwgithub.com/x",                                      // 缺少点
		"https://githu b.com/x",                                        // 主机含空格
		"://github.com/x",                                              // 缺 scheme
		"https:///x",                                                   // 缺主机
		"https://github.comevil/x",                                     // 直接拼到 TLD 后
	}
	for _, u := range bad {
		if err := safeExternalURL(u); err == nil {
			t.Errorf("危险外部链接必须被拒绝，但被放行: %q", u)
		}
	}
}

// TestSafeExternalURL_TrailingDot 结尾点主机名当前策略是保守拒绝，
// 锁定该行为，避免日后误以为它等价于白名单主机。
func TestSafeExternalURL_TrailingDot(t *testing.T) {
	if err := safeExternalURL("https://github.com./x"); err == nil {
		t.Error("带结尾点的白名单主机名当前应被保守拒绝（与精确匹配策略一致）")
	}
}

// TestSafeExternalURL_PathAndQueryUnrestricted 主机合法时，任意路径/查询不应被误拦
// （白名单只约束“去哪儿”，不约束具体页面）。
func TestSafeExternalURL_PathAndQueryUnrestricted(t *testing.T) {
	urls := []string{
		"https://github.com/search?q=openqgl&type=repositories",
		"https://www.minecraft.net/a/b/c/d/e?x=1&y=2#frag",
		"https://api.modrinth.com/v2/project?facets=[[%22project-type:mod%22]]",
	}
	for _, u := range urls {
		if err := safeExternalURL(u); err != nil {
			t.Errorf("合法主机上的路径/查询不应被拦截 %q: %v", u, err)
		}
	}
}

// TestSafeExternalURL_ParserEdgeCases 锁定一些容易被解析器细节绕过的边界：
// scheme 大小写归一、@ 只出现在 query 里不应被当成 userinfo、
// 百分号编码主机名不能用来伪装成白名单主机。
func TestSafeExternalURL_ParserEdgeCases(t *testing.T) {
	accept := []string{
		"HTTPS://github.com/x",                 // scheme 大写会被 url.Parse 归一为 https
		"https://github.com/search?q=a%40b",    // @ 在 query 里是合法数据，不是 userinfo
		"https://api.modrinth.com/?ref=mailto:x@y.com",
	}
	for _, u := range accept {
		if err := safeExternalURL(u); err != nil {
			t.Errorf("边界链接应放行 %q: %v", u, err)
		}
	}
	reject := []string{
		"https://github%2ecom/x", // %2e 编码的点不能还原成白名单主机
		"https://github%2Ecom/x",
	}
	for _, u := range reject {
		if err := safeExternalURL(u); err == nil {
			t.Errorf("百分号编码伪装主机必须被拒绝: %q", u)
		}
	}
}

// TestAllowedExternalHostsImmutable 关键官方主机必须始终在白名单里，
// 防止有人误删后把启动器外链校验整体放哑。
func TestAllowedExternalHostsImmutable(t *testing.T) {
	required := []string{
		"www.minecraft.net", "api.mojang.com", "libraries.minecraft.net",
		"piston-data.mojang.com", "piston-meta.mojang.com",
		"cdn.modrinth.com", "api.modrinth.com",
		"github.com", "raw.githubusercontent.com",
		"bmclapi2.bangbang93.com",
	}
	for _, h := range required {
		if !allowedExternalHosts[h] {
			t.Errorf("关键外部主机 %q 不应从白名单移除", h)
		}
	}
}
