package main

import (
	"net/url"
	"strings"
)

const (
	// maxManifestLibraries 限制单个版本 JSON 中参与审计的库条目数量。
	// 官方清单几十个库，重型 Forge 整合包也就数百；20000 足够大，只用于挡住
	// 故意塞几十万条库把审计 / 下载循环拖死的恶意清单（宁可上限大到不实用）。
	maxManifestLibraries = 20000
	// maxManifestClassifiers 单个库最多审计的 natives 分类数（官方只有
	// windows/linux/osx 等寥寥几个，8 已足够宽裕）。
	maxManifestClassifiers = 8
	// maxManifestInheritDepth inheritsFrom 继承链最大深度，防止环 / 超长链递归。
	maxManifestInheritDepth = 16
)

var allowedVersionMetaHosts = map[string]bool{
	"piston-meta.mojang.com":  true,
	"launchermeta.mojang.com": true, // 旧版元数据主机
	"bmclapi2.bangbang93.com": true, // BMCLAPI 镜像（重写后的目标主机）
}

type manifestSeverity int

const (
	manifestWarn     manifestSeverity = iota // 可继续，但完整性 / 隐私降级
	manifestCritical                         // 必须阻断下载 / 解析
)

type ManifestFinding struct {
	Severity manifestSeverity
	Field    string // 出问题的字段路径，便于审计定位
	Detail   string // 人类可读说明（不含外部输入原文，避免日志注入）
}

// urlOnTrustedHost 判断 URL 是否为 https、无 userinfo、端口合法（缺省或 443）、
// 主机精确命中给定白名单。用 map 精确匹配而非后缀匹配，避免
// evil.libraries.minecraft.net.attacker.com 之类伪造主机绕过。
func urlOnTrustedHost(rawURL string, hosts map[string]bool) bool {
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
	return hosts[host]
}

// auditManifestArtifact 校验一个可执行 jar 产物（client / library artifact /
// native classifier）的路径、URL、SHA1，返回所有命中的问题。
