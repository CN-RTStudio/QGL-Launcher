package main

import (
	"strings"
)

const (
	maxUpdateUrlLen       = 2048              // URL 长度上限
	maxUpdateAssetNameLen = 256               // 发布资产文件名上限
	maxUpdateZipBytes     = 512 * 1024 * 1024 // 更新包总量上限
	maxUpdateZipEntries   = 20000             // 更新包条目上限
	maxUpdateVersionParts = 32                // 版本号拆段上限
	maxUpdateDescRunes    = 2048              // 更新说明长度上限
)

var allowedUpdateHosts = []string{
	"api.github.com",
	"github.com",
	"objects.githubusercontent.com",
	"raw.githubusercontent.com",
	"codeload.github.com",
	"release-assets.githubusercontent.com",
}

type UpdateLimits struct {
	UrlLenMax     int
	AssetNameLen  int
	ZipBytesMax   int64
	ZipEntriesMax int
	VersionParts  int
	DescRunesMax  int
}

func (l UpdateLimits) withDefaults() UpdateLimits {
	if l.UrlLenMax <= 0 {
		l.UrlLenMax = maxUpdateUrlLen
	}
	if l.AssetNameLen <= 0 {
		l.AssetNameLen = maxUpdateAssetNameLen
	}
	if l.ZipBytesMax <= 0 {
		l.ZipBytesMax = maxUpdateZipBytes
	}
	if l.ZipEntriesMax <= 0 {
		l.ZipEntriesMax = maxUpdateZipEntries
	}
	if l.VersionParts <= 0 {
		l.VersionParts = maxUpdateVersionParts
	}
	if l.DescRunesMax <= 0 {
		l.DescRunesMax = maxUpdateDescRunes
	}
	return l
}

// UpdateFindings 是校验结论的条目；Severity 用于 UI 分级（error/warn/info）。
type UpdateFindings struct {
	Severity string // "error" / "warn" / "info"
	Code     string
	Message  string
}

// UpdateVerdict 是一次校验的完整结论。
type UpdateVerdict struct {
	OK             bool
	Findings       []UpdateFindings
	Version        string
	VersionValid   bool
	AssetName      string
	HasSingleRoot  bool
	HasLauncherExe bool
	ZipEntryCount  int
	ZipTotalBytes  int64
}

func sanitizeUpdateUrl(raw string, limits UpdateLimits) (bool, string, string) {
	l := limits.withDefaults()
	if len(raw) > l.UrlLenMax {
		return false, "", "更新 URL 超过长度上限"
	}
	if !strings.HasPrefix(raw, "https://") {
		return false, "", "更新 URL 必须使用 HTTPS"
	}
	rest := raw[len("https://"):]
	if at := strings.Index(rest, "@"); at >= 0 {
		return false, "", "更新 URL 不允许携带用户信息"
	}
	slash := strings.IndexAny(rest, "/?#")
	var hostPort string
	if slash < 0 {
		hostPort = rest
	} else {
		hostPort = rest[:slash]
	}
	host := hostPort
	if idx := strings.LastIndex(hostPort, ":"); idx > 0 && strings.IndexByte(hostPort[idx+1:], ':') < 0 {
		host = hostPort[:idx]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false, "", "更新 URL 缺少主机名"
	}
	// IP 文字形式（IPv4 / IPv6）一律拒绝：更新源必须可审计的域名。
	if isIPLiteralHost(host) {
		return false, "", "更新 URL 不允许 IP 直连"
	}
	if !hostAllowed(host, allowedUpdateHosts) {
		return false, "", "更新源域名不在白名单内"
	}
	return true, host, ""
}

func isIPLiteralHost(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	_, ok := parseDestIP(host)
	return ok
}

// hostAllowed 判断 host 是否等于白名单项或为其子域（label 边界匹配）。
func hostAllowed(host string, allow []string) bool {
	for _, a := range allow {
		a = strings.ToLower(a)
		if host == a {
			return true
		}
		if strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// sanitizeUpdateAssetName 校验发布资产文件名：不得为空、超长、含路径分隔与
// 控制字符。assetName 只允许是一个"文件名"，任何路径形状（含 / \ ..）都拒绝。
func sanitizeUpdateAssetName(name string, limits UpdateLimits) (string, bool) {
	l := limits.withDefaults()
	if name == "" || len(name) > l.AssetNameLen {
		return "", false
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return "", false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return name, true
}
