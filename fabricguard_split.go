package main

import (
	"errors"
	"strconv"
	"strings"
)

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
