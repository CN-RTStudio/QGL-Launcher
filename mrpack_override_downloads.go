package main

import (
	"net/url"
	"strings"
)

func normalizeMrpackDownloads(in []string) ([]string, string) {
	if len(in) == 0 {
		return nil, mrpRejectNoDownload
	}
	if len(in) > maxMrpackMirrorsPerFile {
		return nil, mrpRejectTooManyURLs
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		u0 := strings.TrimSpace(raw)
		if u0 == "" {
			return nil, mrpRejectNoDownload
		}
		if len(u0) > maxMrpackDownloadURLLen {
			return nil, mrpRejectURLTooLong
		}
		if !isHTTPSURL(u0) {
			return nil, mrpRejectURLScheme
		}
		u, err := url.Parse(u0)
		if err != nil {
			return nil, mrpRejectURLScheme
		}
		if u.User != nil {
			return nil, mrpRejectURLUserInfo
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			return nil, mrpRejectURLHost
		}
		// 字符串态先拦一层内网 / 回环（DNS rebinding 由 safeHTTPClient 的拨号闸再兜）。
		if isPrivateDest(u0) {
			return nil, mrpRejectURLPrivate
		}
		norm := strings.ToLower(u.String())
		if seen[norm] {
			return nil, mrpRejectURLDup
		}
		seen[norm] = true
		out = append(out, u0)
	}
	return out, mrpRejectNone
}

var mrpackAllowedDepKeys = map[string]bool{
	"minecraft":     true,
	"forge":         true,
	"neoforge":      true,
	"fabric-loader": true,
	"quilt-loader":  true,
}

// validateMrpackDependencies 校验依赖键集合与各版本标识（复用 nameguard）。
// 通过后把清洗过的值写回 map，供安装流程直接使用。
func validateMrpackDependencies(deps map[string]string) string {
	for k, v := range deps {
		if !mrpackAllowedDepKeys[k] {
			return mrpRejectDepKey
		}
		val := strings.TrimSpace(v)
		if val == "" {
			// 空依赖值没有意义，按坏段处理（minecraft 必填在安装流程另行保证）。
			return mrpRejectBadSegment
		}
		if k == "minecraft" {
			clean, why := SafeVersionComponent(val)
			if why != nameRejectNone {
				return mrpRejectBadSegment
			}
			deps[k] = clean
			continue
		}
		clean, why := SafeLoaderComponent(val)
		if why != nameRejectNone {
			return mrpRejectBadSegment
		}
		deps[k] = clean
	}
	return mrpRejectNone
}

// validateMrpackManifest 对已解析的整合包清单做整体结构校验（就地规范化）。
// 任何越界都返回带中文原因的错误；调用方应中止安装。
