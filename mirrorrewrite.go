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
