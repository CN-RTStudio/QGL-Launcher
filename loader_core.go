package main

import (
	_ "embed"
	"net/url"
	"strings"
)

func isHTTPSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https"
}

var allowedMavenLibHosts = map[string]bool{
	"maven.minecraftforge.net": true,
	"maven.neoforged.net":      true,
	"libraries.minecraft.net":  true,
	"piston-data.mojang.com":   true,
	"maven.fabricmc.net":       true,
	"repo1.maven.org":          true, // Maven Central，部分安装器依赖在此
	"bmclapi2.bangbang93.com":  true, // BMCLAPI 镜像（重写后的目标主机）
}

func isAllowedMavenLibURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.User != nil {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".") // 容忍结尾点，但仍须精确命中
	return allowedMavenLibHosts[host]
}
