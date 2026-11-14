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
