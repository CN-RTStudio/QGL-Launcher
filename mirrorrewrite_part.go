package main

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

// bmclLauncherPrefixRules 供版本清单 / 版本 JSON / 库与资产索引 URL 换源：
// piston-meta、launcher 落到镜像根；libraries.minecraft.net 落到 /maven。
var bmclLauncherPrefixRules = []urlPrefixRule{
	{"https://piston-meta.mojang.com", bmclMirrorBase},
	{"https://launcher.mojang.com", bmclMirrorBase},
	{"https://libraries.minecraft.net", bmclMirrorBase + "/maven"},
}

// rewriteLauncherURLToBMCL 等价原 minecraft.go 的 replaceWithBMCLAPI。
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
