package main

import (
	"path"
	"strings"
)

const (
	loaderArtifactJar = ".jar"
	loaderArtifactExe = ".exe"
	// maxLoaderSlugLen 限制人类可读 slug 的字节长度，给指纹和扩展名留出余量，
	// 保证最终单段文件名远低于常见文件系统 255 字节上限。
	maxLoaderSlugLen = 64
	// loaderURLHashLen 取用 UMFS 256-bit 摘要的前若干十六进制字符做碰撞隔离，
	// 16 个 hex（64 bit）足以区分实际会出现的加载器 URL 数量。
	loaderURLHashLen = 16
	// maxLoaderDestSegLen 是最终单段文件名（slug + "-" + 指纹 + 扩展名）上限。
	maxLoaderDestSegLen = 120
	// loaderFallbackStem 是 slug 无法保留任何安全字符时使用的固定前缀。
	loaderFallbackStem = "loader"
)

// loaderArtifactExt 从下载 URL 的路径部分判定安装器制品扩展名。
// 只认 path 的最后一段，显式忽略 ?query / #fragment，避免 "x.jar?token=.."
// 因字符串后缀不是 ".jar" 而漏判成"无需执行的普通文件"。
func loaderArtifactExt(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	// 这里不做 scheme 判定（调用方已先用 isHTTPSURL 收口），只取路径形态。
	// 用标准库 url.Parse 失败时退化为手工切掉 query/fragment，再做后缀判定。
	pname := ""
	if i := strings.IndexAny(trimmed, "?#"); i >= 0 {
		pname = trimmed[:i]
	} else {
		pname = trimmed
	}
	if s := strings.IndexByte(pname, ':'); s >= 0 {
		// 去掉 scheme:// 前缀，避免把 "https://host/a.exe" 的盘段判断带偏。
		if rest := strings.TrimPrefix(pname[s+1:], "//"); rest != "" {
			pname = rest
		}
	}
	base := strings.ToLower(path.Base(pname))
	switch {
	case strings.HasSuffix(base, loaderArtifactJar):
		return loaderArtifactJar
	case strings.HasSuffix(base, loaderArtifactExe):
		return loaderArtifactExe
	default:
		return ""
	}
}

// sanitizeLoaderSlug 把任意展示名收敛成文件名安全的 slug：
//   - 只保留字母、数字、'-'、'_'、'.'，其余字符（空格、括号、中文、分隔符等）
//     统一折叠成单个 '_'，连续分隔符不重复；
//   - 去掉首尾的 '.'、'_'、'-'，避免 ".." / 隐藏文件 / 结尾点号在 Windows 上
//     被资源管理器吞掉造成同名绕过；
//   - 超长按字节截断后再次修边。
func sanitizeLoaderSlug(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	prevSep := true
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevSep = false
		case r == '-' || r == '_' || r == '.':
			if !prevSep {
				b.WriteRune(r)
				prevSep = true
			}
		default:
			if !prevSep {
				b.WriteByte('_')
				prevSep = true
			}
		}
	}
	slug := strings.Trim(b.String(), "._-")
	if len(slug) > maxLoaderSlugLen {
		slug = strings.Trim(slug[:maxLoaderSlugLen], "._-")
	}
	return slug
}
