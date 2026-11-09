package main

import "testing"

// 这些黄金用例锁定重构前各处手写 strings.Replace 的逐字结果：镜像换源内核只能
// 收敛重复代码，绝不能改变任何一条实际下载 URL（否则会把下载导向错误镜像路径）。

func TestRewriteLauncherURLToBMCL(t *testing.T) {
	const base = "https://bmclapi2.bangbang93.com"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"piston-meta 根换源",
			"https://piston-meta.mojang.com/v1/packages/abc/1.20.json",
			base + "/v1/packages/abc/1.20.json"},
		{"launcher 根换源",
			"https://launcher.mojang.com/v1/objects/abc/client.jar",
			base + "/v1/objects/abc/client.jar"},
		{"libraries 映射到 /maven（无尾斜杠）",
			"https://libraries.minecraft.net/com/mojang/g/1.0/g-1.0.jar",
			base + "/maven/com/mojang/g/1.0/g-1.0.jar"},
		{"非官方主机原样返回",
			"https://example.com/x.jar", "https://example.com/x.jar"},
		{"已是镜像地址不二次改写",
			base + "/maven/com/a.jar", base + "/maven/com/a.jar"},
		{"http 协议不被换源",
			"http://libraries.minecraft.net/a.jar", "http://libraries.minecraft.net/a.jar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rewriteLauncherURLToBMCL(c.in); got != c.want {
				t.Fatalf("rewriteLauncherURLToBMCL(%q)=%q want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRewriteMetaIndexURLToBMCL(t *testing.T) {
	const base = "https://bmclapi2.bangbang93.com"
	cases := []struct {
		in   string
		want string
	}{
		{"https://piston-meta.mojang.com/v1/packages/x/y.json", base + "/v1/packages/x/y.json"},
		{"https://launcher.mojang.com/v1/packages/x/y.json", base + "/v1/packages/x/y.json"},
		// piston-data 不在该规则集内，必须原样返回，防止跨场景误换。
		{"https://piston-data.mojang.com/v1/objects/a/b.jar", "https://piston-data.mojang.com/v1/objects/a/b.jar"},
		{"https://example.com/y.json", "https://example.com/y.json"},
	}
	for _, c := range cases {
		if got := rewriteMetaIndexURLToBMCL(c.in); got != c.want {
			t.Fatalf("rewriteMetaIndexURLToBMCL(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteMappedDataURLToBMCL(t *testing.T) {
	const base = "https://bmclapi2.bangbang93.com"
	cases := []struct {
		in   string
		want string
	}{
		// 服务端 jar / Mappings 保留 /v1/objects 路径（落镜像根，而非 /version）。
		{"https://piston-data.mojang.com/v1/objects/sha/server.jar",
			base + "/v1/objects/sha/server.jar"},
		{"https://launcher.mojang.com/v1/objects/sha/client.txt",
			base + "/v1/objects/sha/client.txt"},
		{"https://piston-meta.mojang.com/v1/objects/sha/x",
			"https://piston-meta.mojang.com/v1/objects/sha/x"},
	}
	for _, c := range cases {
		if got := rewriteMappedDataURLToBMCL(c.in); got != c.want {
			t.Fatalf("rewriteMappedDataURLToBMCL(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteMavenLibURLToBMCL(t *testing.T) {
	const base = "https://bmclapi2.bangbang93.com"
	cases := []struct {
		in   string
		want string
	}{
		{"https://maven.minecraftforge.net/net/minecraftforge/forge/a.jar",
			base + "/maven/net/minecraftforge/forge/a.jar"},
		{"https://maven.neoforged.net/releases/net/neoforged/forge/b.jar",
			base + "/maven/net/neoforged/forge/b.jar"},
		{"https://maven.fabricmc.net/net/fabricmc/c.jar",
			base + "/maven/net/fabricmc/c.jar"},
		// 同规则集内的其它主机规则对当前 URL 必须是 no-op。
		{"https://repo1.maven.org/maven2/x/y.jar", "https://repo1.maven.org/maven2/x/y.jar"},
	}
	for _, c := range cases {
		if got := rewriteMavenLibURLToBMCL(c.in); got != c.want {
			t.Fatalf("rewriteMavenLibURLToBMCL(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteFabricLibURLToBMCL(t *testing.T) {
	const base = "https://bmclapi2.bangbang93.com"
	cases := []struct {
		in   string
		want string
	}{
		{"https://maven.fabricmc.net/a/b.jar", base + "/maven/a/b.jar"},
		{"https://repo1.maven.org/maven2/a/b.jar", base + "/maven/a/b.jar"},
		{"https://libraries.minecraft.net/com/mojang/g.jar", base + "/libraries/com/mojang/g.jar"},
	}
	for _, c := range cases {
		if got := rewriteFabricLibURLToBMCL(c.in); got != c.want {
			t.Fatalf("rewriteFabricLibURLToBMCL(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteSpecializedMirrors(t *testing.T) {
	const base = "https://bmclapi2.bangbang93.com"
	if got := rewriteMavenCentralURLToBMCL("https://repo1.maven.org/maven2/org/x/y-1.jar"); got != base+"/maven/org/x/y-1.jar" {
		t.Fatalf("maven central = %q", got)
	}
	if got := rewriteLibraryArtifactURLToBMCL("https://libraries.minecraft.net/com/mojang/g.jar"); got != base+"/libraries/com/mojang/g.jar" {
		t.Fatalf("library artifact = %q", got)
	}
	cases := []struct {
		in   string
		want string
	}{
		{"https://launcher.mojang.com/v1/objects/h/a", base + "/version/h/a"},
		{"https://piston-data.mojang.com/v1/objects/h/a", base + "/version/h/a"},
		{"https://piston-meta.mojang.com/v1/objects/h/a", base + "/version/h/a"},
		// /v1/packages（资源索引）不匹配 /v1/objects，必须保持原样。
		{"https://piston-meta.mojang.com/v1/packages/h/a", "https://piston-meta.mojang.com/v1/packages/h/a"},
	}
	for _, c := range cases {
		if got := rewriteObjectVersionURLToBMCL(c.in); got != c.want {
			t.Fatalf("object version(%q)=%q want %q", c.in, got, c.want)
		}
	}
	if got := rewriteAssetURLToBMCL("https://resources.download.minecraft.net/ab/abc123"); got != base+"/assets/ab/abc123" {
		t.Fatalf("asset = %q", got)
	}
}

func TestRewriteURLPrefixesEmptyAndIdempotent(t *testing.T) {
	rules := []urlPrefixRule{
		{"", "https://x"}, // 空前缀规则必须被跳过，不能把字符串撑爆
		{"https://a.example/", "https://mirror/a/"},
	}
	first := rewriteURLPrefixes("https://a.example/p", rules)
	if first != "https://mirror/a/p" {
		t.Fatalf("first rewrite = %q", first)
	}
	// 再跑一次：已无任何 from 命中，结果稳定（幂等）。
	if second := rewriteURLPrefixes(first, rules); second != first {
		t.Fatalf("rewrite not idempotent: %q -> %q", first, second)
	}
}

// TestRewriteModMirrorURL 锁定原 mod.go mirrorModURL 的四个 strings.Replace 逐字结果：
// Modrinth CDN/API → /modrinth，CurseForge 两套 CDN → /curseforge，且只替换一次。
func TestRewriteModMirrorURL(t *testing.T) {
	const base = "https://mod.mcimirror.top"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"modrinth cdn",
			"https://cdn.modrinth.com/data/abc/versions/v/a.jar",
			base + "/modrinth/data/abc/versions/v/a.jar"},
		{"modrinth api",
			"https://api.modrinth.com/v2/project/abc",
			base + "/modrinth/v2/project/abc"},
		{"curseforge edge cdn",
			"https://edge.forgecdn.net/files/1/2/a.jar",
			base + "/curseforge/files/1/2/a.jar"},
		{"curseforge mediafilez cdn",
			"https://mediafilez.forgecdn.net/files/1/2/a.jar",
			base + "/curseforge/files/1/2/a.jar"},
		{"无关主机原样返回", "https://example.com/a.jar", "https://example.com/a.jar"},
		{"http 不换源", "http://cdn.modrinth.com/a.jar", "http://cdn.modrinth.com/a.jar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rewriteModMirrorURL(c.in); got != c.want {
				t.Fatalf("rewriteModMirrorURL(%q)=%q want %q", c.in, got, c.want)
			}
		})
	}
}
