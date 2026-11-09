package main

import (
	"fmt"
	"strings"
)

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
