package main

import (
	"strings"
)

// bmclMirrorBase 是 BMCLAPI 镜像的固定根地址（仅 https）。
const bmclMirrorBase = "https://bmclapi2.bangbang93.com"

// urlPrefixRule 表示一条字面前缀替换规则：字符串以 from 开头的片段替换为 to。
type urlPrefixRule struct {
	from string
	to   string
}

// rewriteURLPrefixes 按给定顺序依次应用前缀替换，每条最多替换一次，
// 与历史手写 strings.Replace(url, from, to, 1) 行为完全一致；命中不到的规则跳过。
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
