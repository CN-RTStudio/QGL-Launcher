package main

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

func mrpackOverridePolicy(rel string, isDir bool) string {
	if isDir {
		// 目录本身只要段合法即可；QGL 目录由“其下文件命中”即可整体阻断，
		// 这里对纯目录条目也直接拒绝，避免落地空的 QGL 目录。
		top := strings.SplitN(rel, "/", 2)[0]
		if top == mrpackPrivateSubroot {
			return mrpRejectPrivateDir
		}
		return mrpRejectNone
	}
	segs := strings.Split(rel, "/")
	top := segs[0]
	if top == mrpackPrivateSubroot {
		return mrpRejectPrivateDir
	}
	base := segs[len(segs)-1]
	lower := strings.ToLower(base)
	ext := strings.ToLower(filepath.Ext(base))

	if len(segs) == 1 {
		if mrpackSensitiveRootExts[ext] {
			return mrpRejectRootSensitive
		}
		return mrpRejectNone
	}
	switch top {
	case "mods":
		if !allowedModFileExts[lowerExt(lower)] {
			return mrpRejectBadExt
		}
	case "resourcepacks", "shaderpacks":
		if !mrpackPackArchiveExts[ext] {
			return mrpRejectBadExt
		}
	default:
		if mrpackRunnableExts[ext] {
			return mrpRejectBadExt
		}
	}
	return mrpRejectNone
}

// validateMrpackPlannedEntries 对 overrides 的解压计划逐条施加 mrpackOverridePolicy。
// rel 必须已经过 zipextract 的 secureZipRelPath 段校验（zipPlannedEntry.rel 即此形态）。
func validateMrpackPlannedEntries(plan []zipPlannedEntry) error {
	for _, pe := range plan {
		if why := mrpackOverridePolicy(pe.rel, pe.dir); why != mrpRejectNone {
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
				"mrpackguard", describeMrpackReject(why)+"：overrides/"+pe.rel)
			return fmt.Errorf("%s: overrides/%s", describeMrpackReject(why), pe.rel)
		}
	}
	return nil
}

// lowerExt 返回文件名（已小写）命中的扩展名；对 ".jar.disabled" 这类复合扩展优先返回它。
func lowerExt(lowerName string) string {
	for ext := range allowedModFileExts {
		if strings.HasSuffix(lowerName, ext) {
			return ext
		}
	}
	return filepath.Ext(lowerName)
}

// secureMrpackDestRel 校验并返回可安全拼接到实例目录的 '/'-相对路径。
func secureMrpackDestRel(raw string) (string, string) {
	clean, why := cleanMrpackPathSegments(raw)
	if why != mrpRejectNone {
		return "", why
	}
	if why := mrpackPathPolicy(clean); why != mrpRejectNone {
		return "", why
	}
	return clean, mrpRejectNone
}

// secureMrpackDest 把相对路径安全拼接到实例根目录，并做落盘前的“必须在根内”第二道复核。
func secureMrpackDest(baseDir, raw string) (string, error) {
	rel, why := secureMrpackDestRel(raw)
	if why != mrpRejectNone {
		return "", fmt.Errorf("%s: %s", describeMrpackReject(why), raw)
	}
	dest := filepath.Join(baseDir, filepath.FromSlash(rel))
	if !PathWithinRoot(dest, baseDir) {
		return "", fmt.Errorf("整合包文件解析后越出实例目录: %s", raw)
	}
	return dest, nil
}

// validateMrpackHash 校验单个文件的哈希表：键只能是 sha1/sha512，值必须是对应长度的
// 合法十六进制，且至少提供一个。返回错误原因码。
func validateMrpackHash(hashes map[string]string) string {
	if len(hashes) == 0 {
		return mrpRejectNoHash
	}
	for alg, val := range hashes {
		var wantLen int
		switch alg {
		case "sha1":
			wantLen = 40
		case "sha512":
			wantLen = 128
		default:
			return mrpRejectBadHashAlg
		}
		v := strings.TrimSpace(val)
		if len(v) != wantLen {
			return mrpRejectBadHashValue
		}
		if _, err := hex.DecodeString(v); err != nil {
			return mrpRejectBadHashValue
		}
	}
	if _, ok := hashes["sha1"]; !ok {
		if _, ok512 := hashes["sha512"]; !ok512 {
			return mrpRejectNoHash
		}
	}
	return mrpRejectNone
}

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
