package main

import (
	"testing"
)

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
