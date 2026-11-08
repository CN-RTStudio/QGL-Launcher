package main

import (
	"fmt"
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

// validateMrpackManifest 对已解析的整合包清单做整体结构校验（就地规范化）。
// 任何越界都返回带中文原因的错误；调用方应中止安装。
func validateMrpackManifest(m *ModrinthModpackManifest) error {
	if m == nil {
		return mrpackReject(mrpRejectFormat, "清单为空")
	}
	if m.FormatVersion != 1 {
		return mrpackReject(mrpRejectFormat, fmt.Sprintf("formatVersion=%d", m.FormatVersion))
	}
	if strings.ToLower(strings.TrimSpace(m.Game)) != "minecraft" {
		return mrpackReject(mrpRejectGame, "game="+m.Game)
	}
	if m.Name != "" {
		if containsControlByte(m.Name) {
			return mrpackReject(mrpRejectNameControl, "")
		}
		if len(m.Name) > maxMrpackNameLen {
			return mrpackReject(mrpRejectNameTooLong, "")
		}
	}
	if why := validateMrpackDependencies(m.Dependencies); why != mrpRejectNone {
		return mrpackReject(why, "dependencies")
	}
	if len(m.Files) > maxMrpackIndexFiles {
		return mrpackReject(mrpRejectTooManyFiles, fmt.Sprintf("files=%d", len(m.Files)))
	}

	for i := range m.Files {
		f := &m.Files[i]
		rel, why := secureMrpackDestRel(f.Path)
		if why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d].path=%q", i, f.Path))
		}
		f.Path = rel

		if f.FileSize < 0 || f.FileSize > maxMrpackDeclaredFileSize {
			return mrpackReject(mrpRejectBadFileSize, fmt.Sprintf("files[%d].fileSize=%d", i, f.FileSize))
		}
		if why := validateMrpackHash(f.Hashes); why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d](%s)", i, rel))
		}
		downloads, why := normalizeMrpackDownloads(f.Downloads)
		if why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d](%s)", i, rel))
		}
		f.Downloads = downloads

		// env 只允许 client/server 两个键，取值仅限 required/optional/unsupported；
		// 未知键 / 未知取值就地清除（而非拒绝），避免第三方塞自定义键影响客户端选取。
		if f.Env != nil {
			cleaned := make(map[string]string, 2)
			for _, key := range []string{mrpackEnvKeyClient, mrpackEnvKeyServer} {
				if raw, present := f.Env[key]; present {
					if norm := normalizeMrpackEnvSide(raw); norm != "" {
						cleaned[key] = norm
					}
				}
			}
			if len(cleaned) == 0 {
				f.Env = nil
			} else {
				f.Env = cleaned
			}
		}
	}
	return nil
}
