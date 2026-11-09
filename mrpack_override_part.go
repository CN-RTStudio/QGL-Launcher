package main

import (
	"net/url"
	"strings"
)

// normalizeMrpackDownloads 校验一个文件的下载镜像列表：
// 非空、数量上限、必须 https、无 userinfo、主机有效且不指向内网、规范化后去重。
// 返回清洗后的镜像列表与拒绝原因码。
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

// mrpackAllowedDepKeys 是 dependencies 允许出现的键（Modrinth 规范）。
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
