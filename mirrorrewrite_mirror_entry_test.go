package main

import (
	"testing"
)

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
