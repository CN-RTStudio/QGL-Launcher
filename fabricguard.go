package main

import (
	"errors"
	"strings"
)

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

var fabricMetaHosts = []string{
	"meta.fabricmc.net",
	"maven.fabricmc.net",
	"fabricmc.net",
	"raw.githubusercontent.com",
}

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
