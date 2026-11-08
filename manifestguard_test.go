package main

import "testing"

func TestURLOnTrustedHost(t *testing.T) {
	good := []string{
		"https://libraries.minecraft.net/com/mojang/x.jar",
		"https://bmclapi2.bangbang93.com/version/a/b.jar",
		"https://repo1.maven.org./maven2/x/y.jar", // 结尾点规范化后命中
	}
	for _, u := range good {
		if !urlOnTrustedHost(u, allowedMavenLibHosts) {
			t.Errorf("可信主机被误拒: %s", u)
		}
	}
	bad := []string{
		"http://libraries.minecraft.net/x.jar",                 // 非 https
		"https://user:pass@libraries.minecraft.net/x.jar",      // userinfo
		"https://libraries.minecraft.net:8443/x.jar",           // 非标端口
		"https://evil.libraries.minecraft.net.evil.com/x.jar",  // 后缀伪造
		"https://evil.com/x.jar",                               // 陌生主机
		"",
	}
	for _, u := range bad {
		if urlOnTrustedHost(u, allowedMavenLibHosts) {
			t.Errorf("危险主机被放行: %q", u)
		}
	}
}

func TestAuditManifestArtifact(t *testing.T) {
	good := &LibArtifact{
		Path: "com/mojang/foo/1.0/foo-1.0.jar",
		URL:  "https://libraries.minecraft.net/com/mojang/foo/1.0/foo-1.0.jar",
		SHA1: "0123456789abcdef0123456789abcdef01234567",
	}
	if fs := auditManifestArtifact("lib", true, good, allowedMavenLibHosts); len(fs) != 0 {
		t.Fatalf("合法产物被误报: %+v", fs)
	}

	cases := []struct {
		name string
		art  *LibArtifact
	}{
		{"evil-host", &LibArtifact{Path: good.Path, URL: "https://evil.com/x.jar", SHA1: good.SHA1}},
		{"http-url", &LibArtifact{Path: good.Path, URL: "http://libraries.minecraft.net/x.jar", SHA1: good.SHA1}},
		{"empty-sha1", &LibArtifact{Path: good.Path, URL: good.URL, SHA1: ""}},
		{"bad-sha1", &LibArtifact{Path: good.Path, URL: good.URL, SHA1: "XYZ"}},
		{"traversal-path", &LibArtifact{Path: "../../etc/x.jar", URL: good.URL, SHA1: good.SHA1}},
		{"backslash-path", &LibArtifact{Path: "com\\..\\x.jar", URL: good.URL, SHA1: good.SHA1}},
	}
	for _, c := range cases {
		fs := auditManifestArtifact("lib", true, c.art, allowedMavenLibHosts)
		if !manifestHasCritical(fs) {
			t.Errorf("用例 %s 应产生 critical，实际: %+v", c.name, fs)
		}
	}

	// client 产物不带 path，checkRelPath=false 时不应报路径问题。
	client := &LibArtifact{
		URL:  "https://piston-data.mojang.com/v1/objects/abc/client.jar",
		SHA1: "0123456789abcdef0123456789abcdef01234567",
	}
	if fs := auditManifestArtifact("downloads.client", false, client, allowedMavenLibHosts); len(fs) != 0 {
		t.Fatalf("合法 client 被误报: %+v", fs)
	}
}

func TestAuditVersionManifestClean(t *testing.T) {
	vj := &VersionJSON{
		Downloads: &VersionDownloads{
			Client: &LibArtifact{
				URL:  "https://piston-data.mojang.com/v1/objects/a/client.jar",
				SHA1: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		Libraries: []Library{
			{Downloads: &LibDownloads{
				Artifact: &LibArtifact{
					Path: "com/mojang/b/1.0/b-1.0.jar",
					URL:  "https://libraries.minecraft.net/com/mojang/b/1.0/b-1.0.jar",
					SHA1: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
				Classifiers: map[string]*LibArtifact{
					"windows": {
						Path: "com/mojang/b/1.0/b-1.0-natives-windows.jar",
						URL:  "https://bmclapi2.bangbang93.com/maven/com/mojang/b/1.0/b-1.0-natives-windows.jar",
						SHA1: "cccccccccccccccccccccccccccccccccccccccc",
					},
				},
			}},
		},
		AssetIndex: &AssetIndexRef{
			ID:   "17",
			URL:  "https://piston-meta.mojang.com/v1/packages/x/17.json",
			SHA1: "dddddddddddddddddddddddddddddddddddddddd",
		},
	}
	fs := auditVersionManifest(vj)
	if manifestHasCritical(fs) {
		t.Fatalf("干净清单被误判 critical: %+v", fs)
	}
}

func TestAuditVersionManifestAttacks(t *testing.T) {
	// 库主机指向攻击者服务器。
	vj := &VersionJSON{
		Libraries: []Library{
			{Downloads: &LibDownloads{
				Artifact: &LibArtifact{
					Path: "x/y/1/1.jar",
					URL:  "https://attacker.example/x.jar",
					SHA1: "0123456789abcdef0123456789abcdef01234567",
				},
			}},
		},
		AssetIndex: &AssetIndexRef{
			ID:  "../escape",
			URL: "https://evil.com/idx.json",
		},
	}
	fs := auditVersionManifest(vj)
	if !manifestHasCritical(fs) {
		t.Fatalf("恶意清单应含 critical: %+v", fs)
	}
	// 必须同时点出库主机与资源索引两处问题。
	fields := map[string]bool{}
	for _, f := range fs {
		fields[f.Field] = true
	}
	for _, want := range []string{"libraries[0].artifact.url", "assetIndex.id", "assetIndex.url"} {
		if !fields[want] {
			t.Errorf("缺少字段问题 %s，实际字段: %v", want, fields)
		}
	}
	if err := manifestCriticalError(fs); err == nil {
		t.Fatal("critical 问题应汇总成 error")
	}
}

func TestAuditVersionManifestLibraryCap(t *testing.T) {
	vj := &VersionJSON{Libraries: make([]Library, maxManifestLibraries+1)}
	fs := auditVersionManifest(vj)
	if !manifestHasCritical(fs) {
		t.Fatalf("超量库清单应判 critical")
	}
}

func TestSafeVersionName(t *testing.T) {
	good := []string{"1.21", "1.21-Forge 47.2", "整合包 v2", "1.0..2"}
	for _, n := range good {
		if safeVersionName(n) == "" {
			t.Errorf("合法版本名被误拒: %q", n)
		}
	}
	bad := []string{"", "  ", ".", "..", "a/b", `..\x`, `C:\windows\x`, "a:b", "a\x00b"}
	for _, n := range bad {
		if safeVersionName(n) != "" {
			t.Errorf("非法版本名被放行: %q", n)
		}
	}
}

func TestValidateInheritStep(t *testing.T) {
	seen := map[string]bool{}

	parent, err := validateInheritStep("1.21", 0, seen)
	if err != nil || parent != "1.21" {
		t.Fatalf("正常继承被拒: %v", err)
	}
	seen["1.21"] = true

	bad := []string{
		"../evil",        // 穿越
		"a/b",            // 分隔符
		"..",             // 父目录
		"C:\\windows\\x", // 盘符 / 反斜杠
		"a:b",            // 冒号
		"",               // 空
	}
	for _, id := range bad {
		if _, err := validateInheritStep(id, 0, map[string]bool{}); err == nil {
			t.Errorf("非法父版本名被放行: %q", id)
		}
	}

	// 成环。
	if _, err := validateInheritStep("1.21", 1, seen); err == nil {
		t.Fatal("循环继承未被发现")
	}
	// 超深。
	if _, err := validateInheritStep("deep", maxManifestInheritDepth, map[string]bool{}); err == nil {
		t.Fatal("继承链超深未被拦截")
	}
}
