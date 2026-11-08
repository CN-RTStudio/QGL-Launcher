package main

// manifestguard.go —— 不受信任版本清单（version.json）的统一安全收口。
//
// 威胁模型：
//   AddToDownloadList / DownloadVersion 的 versionURL 可由前端指向任意第三方镜像
//   甚至攻击者控制的站点。版本 JSON 中每个 client / library / native / assetIndex
//   的 url、path、sha1 全部由清单作者填写。历史上这些下载 URL 只做了 BMCLAPI 重写，
//   没有任何可信主机校验：攻击者只要能让启动器加载自己的 version.json，就能把某个
//   library 的 url 指向自己的服务器，jar 落进 libraries 后进入 JVM classpath，
//   等同远程代码执行；清单自带的 sha1 同样是攻击者写的，不能充当信任锚。
//   此外 inheritsFrom 会被直接拼进文件路径（路径穿越），且解析无深度 / 环检测，
//   恶意清单可造成越权读取或无限递归爆栈。
//
// 本模块只做纯判定（不发请求、不落盘），由 DownloadVersion / resolveVersionJSON
// 在真正下载 / 读盘前调用：critical 一律阻断，warn 记审计后继续。

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

// allowedVersionMetaHosts 允许下载版本 JSON / 资源索引（纯元数据）的主机。
var allowedVersionMetaHosts = map[string]bool{
	"piston-meta.mojang.com":  true,
	"launchermeta.mojang.com": true, // 旧版元数据主机
	"bmclapi2.bangbang93.com": true, // BMCLAPI 镜像（重写后的目标主机）
}

// manifestSeverity 清单问题严重级别。
type manifestSeverity int

const (
	manifestWarn manifestSeverity = iota // 可继续，但完整性 / 隐私降级
	manifestCritical                     // 必须阻断下载 / 解析
)

// ManifestFinding 描述清单中一处安全问题。
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

// auditManifestURL 校验下载 URL 是否落在可信主机，返回 critical 问题；无问题返回 nil。
func auditManifestURL(field string, rawURL string, hosts map[string]bool) *ManifestFinding {
	if strings.TrimSpace(rawURL) == "" {
		return &ManifestFinding{manifestCritical, field, "下载 URL 为空"}
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return &ManifestFinding{manifestCritical, field, "下载 URL 无法解析"}
	}
	if u.Scheme != "https" {
		return &ManifestFinding{manifestCritical, field, "下载 URL 不是 https，存在中间人篡改风险"}
	}
	if u.User != nil {
		return &ManifestFinding{manifestCritical, field, "下载 URL 不允许携带 userinfo"}
	}
	if port := u.Port(); port != "" && port != "443" {
		return &ManifestFinding{manifestCritical, field, "下载 URL 端口非默认 443"}
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !hosts[host] {
		return &ManifestFinding{manifestCritical, field, "下载主机不在可信白名单内"}
	}
	return nil
}

// auditManifestHash 校验清单声明的 SHA1：可执行产物（client / library / native jar）
// 必须提供 40 位小写十六进制，空值直接免校验是明确的完整性缺口（critical）；
// 给了但格式非法同样 critical（会让后续校验逻辑行为不可预期）。
func auditManifestHash(field string, sha1 string) *ManifestFinding {
	h := strings.TrimSpace(sha1)
	if h == "" {
		return &ManifestFinding{manifestCritical, field, "可执行下载缺少 SHA1，无法校验完整性"}
	}
	if !IsLowerHex(h, 40) {
		return &ManifestFinding{manifestCritical, field, "SHA1 不是 40 位小写十六进制"}
	}
	return nil
}

// auditManifestRelPath 校验库 / native 的相对路径必须通过严格 Maven 路径白名单。
func auditManifestRelPath(field string, relPath string) *ManifestFinding {
	if SafeMavenRelPath(relPath) == "" {
		return &ManifestFinding{manifestCritical, field, "库路径含穿越 / 盘符 / 反斜杠等非法成分"}
	}
	return nil
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
