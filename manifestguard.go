package main

import (
	"fmt"
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
func auditManifestArtifact(field string, checkRelPath bool, art *LibArtifact, hosts map[string]bool) []ManifestFinding {
	if art == nil {
		return nil
	}
	var out []ManifestFinding
	if checkRelPath {
		if f := auditManifestRelPath(field+".path", art.Path); f != nil {
			out = append(out, *f)
		}
	}
	if f := auditManifestURL(field+".url", art.URL, hosts); f != nil {
		out = append(out, *f)
	}
	if f := auditManifestHash(field+".sha1", art.SHA1); f != nil {
		out = append(out, *f)
	}
	return out
}

// auditVersionManifest 对整份版本 JSON 做安全审计，返回全部问题（critical/warn）。
// 迭代数量有界，避免恶意超大清单把审计本身拖成 DoS。
func auditVersionManifest(vj *VersionJSON) []ManifestFinding {
	if vj == nil {
		return []ManifestFinding{{manifestCritical, "$", "版本 JSON 为空"}}
	}
	var out []ManifestFinding

	// client / server jar：可执行，走 Maven 可信主机集。
	if vj.Downloads != nil {
		if f := auditManifestArtifact("downloads.client", false, vj.Downloads.Client, allowedMavenLibHosts); f != nil {
			out = append(out, f...)
		}
		// server 不参与客户端启动流程，但若清单给了就同样要求自洽。
		if vj.Downloads.Server != nil {
			if f := auditManifestArtifact("downloads.server", false, vj.Downloads.Server, allowedMavenLibHosts); f != nil {
				out = append(out, f...)
			}
		}
	}

	// 库 / native 数量有界。
	if len(vj.Libraries) > maxManifestLibraries {
		out = append(out, ManifestFinding{manifestCritical, "libraries",
			fmt.Sprintf("库条目数量超过 %d 上限", maxManifestLibraries)})
	}
	libCount := len(vj.Libraries)
	if libCount > maxManifestLibraries {
		libCount = maxManifestLibraries
	}
	for i := 0; i < libCount; i++ {
		lib := &vj.Libraries[i]
		if lib.Downloads == nil {
			continue
		}
		if lib.Downloads.Artifact != nil {
			field := fmt.Sprintf("libraries[%d].artifact", i)
			out = append(out, auditManifestArtifact(field, true, lib.Downloads.Artifact, allowedMavenLibHosts)...)
		}
		if len(lib.Downloads.Classifiers) > maxManifestClassifiers {
			out = append(out, ManifestFinding{manifestWarn,
				fmt.Sprintf("libraries[%d].classifiers", i), "native 分类数量异常多，仅审计前若干项"})
		}
		c := 0
		for name, art := range lib.Downloads.Classifiers {
			if c >= maxManifestClassifiers {
				break
			}
			c++
			if art == nil {
				continue
			}
			field := fmt.Sprintf("libraries[%d].classifiers[%s]", i, name)
			out = append(out, auditManifestArtifact(field, true, art, allowedMavenLibHosts)...)
		}
	}

	// 资源索引：ID 会拼进本地文件路径，URL 走元数据主机集。
	if vj.AssetIndex != nil {
		idx := vj.AssetIndex
		if SafeSimpleName(idx.ID) == "" {
			out = append(out, ManifestFinding{manifestCritical, "assetIndex.id", "资源索引 ID 不是单段安全名"})
		}
		if f := auditManifestURL("assetIndex.url", idx.URL, allowedVersionMetaHosts); f != nil {
			out = append(out, *f)
		}
		if h := strings.TrimSpace(idx.SHA1); h != "" && !IsLowerHex(h, 40) {
			out = append(out, ManifestFinding{manifestCritical, "assetIndex.sha1", "资源索引 SHA1 格式非法"})
		}
	}
	return out
}
