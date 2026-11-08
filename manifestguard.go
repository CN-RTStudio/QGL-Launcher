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
