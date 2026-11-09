package main

import (
	"net/url"
	"strings"
)

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
