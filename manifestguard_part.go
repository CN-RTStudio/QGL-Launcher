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

// manifestHasCritical 判断问题集中是否含 critical。
func manifestHasCritical(findings []ManifestFinding) bool {
	for i := range findings {
		if findings[i].Severity == manifestCritical {
			return true
		}
	}
	return false
}

// manifestCriticalError 把 critical 问题汇总成一个可返回的错误，只带字段名与
// 固定说明，不拼接外部可控字符串。
func manifestCriticalError(findings []ManifestFinding) error {
	n := 0
	fields := make([]string, 0, 8)
	for i := range findings {
		if findings[i].Severity != manifestCritical {
			continue
		}
		n++
		if len(fields) < 8 {
			fields = append(fields, findings[i].Field)
		}
	}
	if n == 0 {
		return nil
	}
	return fmt.Errorf("版本清单存在 %d 处严重安全问题，已拒绝下载（涉及字段: %s）", n, strings.Join(fields, ", "))
}

// safeVersionName 校验版本 / 继承父版本的目录名。与资源索引 ID 走的严格 Maven
// 字符集不同：自定义版本名允许空格、中文等（sanitizeVersionName 也保留它们），
// 这里只做“越出 versions/ 目录”所需的最小约束——拒分隔符（/ \）、冒号（盘符 /
// NTFS ADS）、NUL 与控制字符、空段、"."/".."。没有分隔符时，名字里出现 ".."
// 子串（如 "1.0..2"）仍是 versions/ 下的单段目录，不构成穿越。
func safeVersionName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 256 {
		return ""
	}
	if s == "." || s == ".." || strings.ContainsAny(s, `/\:`) {
		return ""
	}
	for _, r := range s {
		if r == 0 || r < 0x20 {
			return ""
		}
	}
	return s
}

// validateInheritStep 校验 inheritsFrom 链上的下一步：父 ID 必须是安全的单段版本名
// （拒盘符 / 分隔符 / "." / ".." 穿越），深度受限，且不允许成环。
// 返回清洗后的父 ID。
func validateInheritStep(parentID string, depth int, seen map[string]bool) (string, error) {
	if depth >= maxManifestInheritDepth {
		return "", fmt.Errorf("版本继承链超过 %d 层，疑似恶意嵌套", maxManifestInheritDepth)
	}
	safe := safeVersionName(parentID)
	if safe == "" {
		return "", fmt.Errorf("inheritsFrom 不是合法的单段版本名，拒绝解析")
	}
	if seen[safe] {
		return "", fmt.Errorf("版本继承链存在循环引用，拒绝解析")
	}
	return safe, nil
}
