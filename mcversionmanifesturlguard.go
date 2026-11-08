package main

// mcversionmanifesturlguard.go —— 版本清单 / 资源 URL 白名单。
//
// 启动器要从 Mojang、Forge、Fabric 的清单里解析出下载 URL。清单本身是 JSON，
// 如果有人把本地配置里的 manifest 指向 file:// 或内网 http://，启动器会
// 去拉本地任意文件并落到 .minecraft 里。这里只允许已知的官方 CDN 主机。

import (
	"net/url"
	"strings"
)

// allowedManifestHosts 允许作为版本/资源清单来源的主机。
var allowedManifestHosts = map[string]bool{
	"piston-meta.mojang.com":           true,
	"piston-data.mojang.com":           true,
	"launchermeta.mojang.com":          true,
	"libraries.minecraft.net":          true,
	"resources.download.minecraft.net": true,
	"files.minecraftforge.net":         true,
	"maven.minecraftforge.net":         true,
	"meta.fabricmc.net":                true,
	"maven.fabricmc.net":               true,
	"quiltmc.org":                      true,
	"maven.quiltmc.org":                true,
	"neoforged.net":                    true,
	"maven.neoforged.net":              true,
}

// IsAllowedManifestURL 判断 URL 是否允许被启动器当作版本/资源清单拉取。
// 不允许 file://、data:、回环、内网私网。
func IsAllowedManifestURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if !allowedManifestHosts[host] {
		return false
	}
	return true
}

// NormalizeManifestURL 把清单里的路径统一成 https，去掉默认端口。
func NormalizeManifestURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	if !IsAllowedManifestURL(u.String()) {
		return "", false
	}
	u.Scheme = "https"
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), true
}
