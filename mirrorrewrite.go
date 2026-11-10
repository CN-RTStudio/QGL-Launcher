package main

import (
	"strings"
)

const bmclMirrorBase = "https://bmclapi2.bangbang93.com"

type urlPrefixRule struct {
	from string
	to   string
}

func rewriteURLPrefixes(raw string, rules []urlPrefixRule) string {
	out := raw
	for _, rule := range rules {
		if rule.from == "" {
			continue
		}
		if !strings.HasPrefix(out, rule.from) {
			continue
		}
		if mirrorRuleEndsAtHost(rule.from) && !mirrorPrefixEndsAtHostBoundary(out[len(rule.from):]) {
			continue
		}
		out = strings.Replace(out, rule.from, rule.to, 1)
	}
	return out
}
func mirrorRuleEndsAtHost(from string) bool {
	idx := strings.Index(from, "://")
	if idx < 0 {
		return false
	}
	rest := from[idx+3:]
	return !strings.ContainsAny(rest, "/?#")
}

func rewriteLauncherURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclLauncherPrefixRules)
}

// bmclMetaIndexPrefixRules 供服务端版本 JSON 与客户端资源索引 JSON：
// piston-meta、launcher 主机整体落到镜像根（保留其下 /v1/... 路径）。
var bmclMetaIndexPrefixRules = []urlPrefixRule{
	{"https://piston-meta.mojang.com", bmclMirrorBase},
	{"https://launcher.mojang.com", bmclMirrorBase},
}

// rewriteMetaIndexURLToBMCL 把元数据 / 索引主机换到镜像根。
func rewriteMetaIndexURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMetaIndexPrefixRules)
}

// bmclMappedDataPrefixRules 供服务端 jar 与 Mappings 文件：piston-data、launcher
// 主机整体落到镜像根（保留 /v1/objects/... 路径，不做 /version 收敛）。
var bmclMappedDataPrefixRules = []urlPrefixRule{
	{"https://piston-data.mojang.com", bmclMirrorBase},
	{"https://launcher.mojang.com", bmclMirrorBase},
}

func rewriteMappedDataURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMappedDataPrefixRules)
}

var bmclMavenLibPrefixRules = []urlPrefixRule{
	{"https://maven.minecraftforge.net/", bmclMirrorBase + "/maven/"},
	{"https://maven.neoforged.net/releases/", bmclMirrorBase + "/maven/"},
	{"https://maven.fabricmc.net/", bmclMirrorBase + "/maven/"},
}

func rewriteMavenLibURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMavenLibPrefixRules)
}

var bmclFabricLibPrefixRules = []urlPrefixRule{
	{"https://maven.fabricmc.net/", bmclMirrorBase + "/maven/"},
	{"https://repo1.maven.org/maven2/", bmclMirrorBase + "/maven/"},
	{"https://libraries.minecraft.net/", bmclMirrorBase + "/libraries/"},
}

func rewriteFabricLibURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclFabricLibPrefixRules)
}

var bmclMavenCentralPrefixRules = []urlPrefixRule{
	{"https://repo1.maven.org/maven2/", bmclMirrorBase + "/maven/"},
}

func rewriteMavenCentralURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMavenCentralPrefixRules)
}

var bmclLibraryArtifactPrefixRules = []urlPrefixRule{
	{"https://libraries.minecraft.net/", bmclMirrorBase + "/libraries/"},
}

func rewriteLibraryArtifactURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclLibraryArtifactPrefixRules)
}

// bmclObjectVersionPrefixRules 供 getMirrorURLs 的 Mojang 对象分支：三个对象主机
// 的 /v1/objects/ 前缀统一落到镜像 /version/（只替换该段路径，前缀不匹配时不动）。
var bmclObjectVersionPrefixRules = []urlPrefixRule{
	{"https://launcher.mojang.com/v1/objects/", bmclMirrorBase + "/version/"},
	{"https://piston-data.mojang.com/v1/objects/", bmclMirrorBase + "/version/"},
	{"https://piston-meta.mojang.com/v1/objects/", bmclMirrorBase + "/version/"},
}

// rewriteObjectVersionURLToBMCL 把 Mojang 对象存储的 /v1/objects/ 换到 /version/。
func rewriteObjectVersionURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclObjectVersionPrefixRules)
}

// bmclAssetPrefixRules 供资源对象（resources.download.minecraft.net）落 /assets/。
var bmclAssetPrefixRules = []urlPrefixRule{
	{"https://resources.download.minecraft.net/", bmclMirrorBase + "/assets/"},
}

// rewriteAssetURLToBMCL 把资源对象主机换到镜像 /assets/。
func rewriteAssetURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclAssetPrefixRules)
}

// ===== Modrinth / CurseForge 中国镜像（mcimirror）换源 =====
//
// Mod 下载原来在 mod.go 里有一份独立的 mirrorModURL，用四个 strings.Replace 把
// Modrinth 的 CDN/API 与 CurseForge 的两套 CDN 主机改写为 mcimirror 镜像。它与
// BMCLAPI 换源是完全同一类"按有序源前缀做一次性字面替换"，为避免换源规则在多文件
// 各写一份（此前 BMCLAPI 已因此散落二十余处），这里统一收口到本内核，mod.go /
// modpack.go 只调用 rewriteModMirrorURL。

// modMirrorBase 是 Mod/整合包镜像 mcimirror 的固定根地址（仅 https）。
const modMirrorBase = "https://mod.mcimirror.top"

// modMirrorPrefixRules 保持与历史 mirrorModURL 完全一致的替换语义与顺序。
// Modrinth 的 CDN 与 API 都落到 /modrinth；CurseForge 两套 CDN 都落到 /curseforge。
var modMirrorPrefixRules = []urlPrefixRule{
	{"https://cdn.modrinth.com", modMirrorBase + "/modrinth"},
	{"https://api.modrinth.com", modMirrorBase + "/modrinth"},
	{"https://edge.forgecdn.net", modMirrorBase + "/curseforge"},
	{"https://mediafilez.forgecdn.net", modMirrorBase + "/curseforge"},
}

// rewriteModMirrorURL 等价原 mod.go 的 mirrorModURL：把 Modrinth/CurseForge
// 官方主机一次性改写为 mcimirror 镜像；不匹配的地址原样返回。
func rewriteModMirrorURL(raw string) string {
	return rewriteURLPrefixes(raw, modMirrorPrefixRules)
}

func mirrorPrefixEndsAtHostBoundary(rest string) bool {
	if rest == "" {
		return true
	}
	switch rest[0] {
	case '/', '?', '#', ':':
		return true
	default:
		return false
	}
}

var bmclLauncherPrefixRules = []urlPrefixRule{
	{"https://piston-meta.mojang.com", bmclMirrorBase},
	{"https://launcher.mojang.com", bmclMirrorBase},
	{"https://libraries.minecraft.net", bmclMirrorBase + "/maven"},
}
