package main

// fabricguard.go —— Fabric 加载器版本字符串与元数据地址校验内核。
//
// 背景：
//   Fabric 的安装链路是"元数据 JSON -> 加载器 jar / 中间件 jar / 启动库"，
//   版本标识来自远端清单与用户选择。攻击面集中在：
//     1) 版本字符串注入：恶意清单把 loader 版本写成含路径/控制字符/超长串，
//        拼接进下载 URL 或本地目录名后会越界写文件或请求被篡改的地址；
//     2) 元数据地址投毒：镜像/中间人把 meta.fabricmc.net 换成别的 host，
//        让启动器从不可信来源拉取清单与 jar（供应链起点被污染，比单个 jar
//        哈希被改更根本）；
//     3) 版本比较陷阱：loader "0.14.9" < "0.14.10" 的字典序问题会选错版本
//        或让降级检查失效。
//   本模块对版本字符串、maven 路径段、元数据 URL 三处做收口，比较逻辑与
//   updateguard 的版本比较同源（数字段数值比较）。

import (
	"errors"
	"strconv"
	"strings"
)

// FabricLimits 限定 Fabric 版本与 URL 的输入边界。
type FabricLimits struct {
	MaxVersionRunes  int
	MaxUrlRunes      int
	MaxPathSegments  int
	MaxSegmentRunes  int
}

func (l *FabricLimits) withDefaults() FabricLimits {
	if l == nil {
		l = &FabricLimits{}
	}
	out := *l
	if out.MaxVersionRunes <= 0 {
		out.MaxVersionRunes = 64
	}
	if out.MaxUrlRunes <= 0 {
		out.MaxUrlRunes = 2048
	}
	if out.MaxPathSegments <= 0 {
		out.MaxPathSegments = 8
	}
	if out.MaxSegmentRunes <= 0 {
		out.MaxSegmentRunes = 120
	}
	return out
}

// fabricMetaHosts 是允许作为 Fabric 元数据/构件来源的官方主机。
var fabricMetaHosts = []string{
	"meta.fabricmc.net",
	"maven.fabricmc.net",
	"fabricmc.net",
	"raw.githubusercontent.com",
}

// ValidateFabricVersionString 校验 loader/游戏版本字符串：只允许数字点段与可选
// 预发布后缀（-alpha/-beta/-rc/-pre 加数字），拒控制字符、路径、超长。
func ValidateFabricVersionString(v string, lim FabricLimits) (string, error) {
	d := lim.withDefaults()
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return "", errors.New("fabric version is empty")
	}
	if len([]rune(trimmed)) > d.MaxVersionRunes {
		return "", errors.New("fabric version too long")
	}
	if hasControlCharStr(trimmed) {
		return "", errors.New("fabric version contains control characters")
	}
	if strings.ContainsAny(trimmed, `/\`) {
		return "", errors.New("fabric version must not contain path separators")
	}
	// 拆预发布后缀：主段 + 可选 -suffix
	mainPart := trimmed
	suffix := ""
	if i := strings.LastIndexByte(trimmed, '-'); i > 0 {
		mainPart = trimmed[:i]
		suffix = trimmed[i:]
		if !isPrereleaseSuffix(suffix) {
			return "", errors.New("fabric version has invalid prerelease suffix")
		}
	}
	if !isDottedNumber(mainPart) {
		return "", errors.New("fabric version must be dotted numbers")
	}
	return trimmed, nil
}

// isPrereleaseSuffix 校验 -alphaN / -betaN / -rcN / -preN 形式的后缀。
func isPrereleaseSuffix(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	rest := s[1:]
	for _, prefix := range []string{"alpha", "beta", "rc", "pre"} {
		if strings.HasPrefix(rest, prefix) {
			num := rest[len(prefix):]
			if num == "" {
				return true // -beta 允许不带数字
			}
			return isDigits(num)
		}
	}
	return false
}

// isDottedNumber 校验形如 1 / 1.19 / 0.14.24 的数字点段串。
func isDottedNumber(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 8 {
		return false
	}
	for _, p := range parts {
		if p == "" || !isDigits(p) {
			return false
		}
	}
	return true
}

// isDigits 校验纯数字串（允许前导零）。
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// CompareFabricVersions 比较两个主版本（忽略预发布后缀差异时用 equal 参数）。
// 返回 -1 / 0 / 1；数字段按数值比较，段数不同则缺段按 0。
func CompareFabricVersions(a, b string) int {
	pa := splitVersionSegments(a)
	pb := splitVersionSegments(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var na, nb int64
		if i < len(pa) {
			na, _ = strconv.ParseInt(pa[i], 10, 64)
		}
		if i < len(pb) {
			nb, _ = strconv.ParseInt(pb[i], 10, 64)
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

// splitVersionSegments 把主版本拆成数字段（去掉预发布后缀）。
func splitVersionSegments(v string) []string {
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	return strings.Split(v, ".")
}

// ValidateFabricMetaUrl 校验元数据/构件 URL：https + 白名单主机 + 路径段净化。
func ValidateFabricMetaUrl(url string, lim FabricLimits) (string, error) {
	d := lim.withDefaults()
	if len([]rune(url)) > d.MaxUrlRunes {
		return "", errors.New("fabric url too long")
	}
	if hasControlCharStr(url) {
		return "", errors.New("fabric url contains control characters")
	}
	if !strings.HasPrefix(url, "https://") {
		return "", errors.New("fabric url must be https")
	}
	rest := url[len("https://"):]
	slash := strings.IndexByte(rest, '/')
	host := rest
	path := ""
	if slash >= 0 {
		host = rest[:slash]
		path = rest[slash+1:]
	}
	matched := false
	hl := strings.ToLower(host)
	for _, allowed := range fabricMetaHosts {
		if hl == allowed || strings.HasSuffix(hl, "."+allowed) {
			matched = true
			break
		}
	}
	if !matched {
		return "", errors.New("fabric url host not allowed")
	}
	segments := strings.Split(path, "/")
	if len(segments) > d.MaxPathSegments {
		return "", errors.New("fabric url path too deep")
	}
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if len([]rune(seg)) > d.MaxSegmentRunes {
			return "", errors.New("fabric url path segment too long")
		}
		if hasControlCharStr(seg) {
			return "", errors.New("fabric url path contains control characters")
		}
	}
	return url, nil
}

// ValidateFabricArtifactSegment 校验 maven 坐标单段（groupId/artifactId/version）。
func ValidateFabricArtifactSegment(seg string, lim FabricLimits) (string, error) {
	d := lim.withDefaults()
	if strings.TrimSpace(seg) == "" {
		return "", errors.New("artifact segment is empty")
	}
	if len([]rune(seg)) > d.MaxSegmentRunes {
		return "", errors.New("artifact segment too long")
	}
	if hasControlCharStr(seg) {
		return "", errors.New("artifact segment contains control characters")
	}
	if strings.ContainsAny(seg, `/\`) || strings.Contains(seg, "..") {
		return "", errors.New("artifact segment must be a single component")
	}
	return seg, nil
}

// SummarizeFabricError 把 Fabric 校验错误压成一行可读文本。
func SummarizeFabricError(err error) string {
	if err == nil {
		return "fabric check ok"
	}
	return "fabric check rejected: " + err.Error()
}
