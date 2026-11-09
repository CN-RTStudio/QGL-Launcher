package main

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
