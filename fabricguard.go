package main

import (
	"errors"
	"strings"
)

// FabricLimits 限定 Fabric 版本与 URL 的输入边界。
type FabricLimits struct {
	MaxVersionRunes int
	MaxUrlRunes     int
	MaxPathSegments int
	MaxSegmentRunes int
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
