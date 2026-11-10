package main

import (
	"path"
	"path/filepath"
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

func buildLoaderDestName(customName, rawURL, ext string) string {
	slug := sanitizeLoaderSlug(customName)
	if slug == "" {
		slug = loaderFallbackStem
	}
	sum := umfsHash([]byte(strings.TrimSpace(rawURL)))
	if len(sum) > loaderURLHashLen {
		sum = sum[:loaderURLHashLen]
	}
	// 预留 "-" + 指纹 + 扩展名 的长度，超长时继续削短 slug。
	reserved := 1 + len(sum) + len(ext)
	if len(slug)+reserved > maxLoaderDestSegLen {
		keep := maxLoaderDestSegLen - reserved
		if keep < 1 {
			keep = 1
		}
		if len(slug) > keep {
			slug = strings.Trim(slug[:keep], "._-")
		}
		if slug == "" {
			slug = loaderFallbackStem
		}
	}
	return slug + "-" + sum + ext
}

func resolveLoaderTempDest(tempDir, customName, rawURL string) (string, bool) {
	root := filepath.Clean(tempDir)
	if root == "" || root == "." || root == string(filepath.Separator) {
		return "", false
	}
	ext := loaderArtifactExt(rawURL)
	name := buildLoaderDestName(customName, rawURL, ext)
	// 最终单段必须通过统一的安全段校验：字符白名单、非 ".."、非 Windows
	// 保留设备名、结尾不留点 / 空格。理论上指纹后缀已使其不可能命中保留名，
	// 这里仍统一过一遍，保持单一裁决入口。
	if !validateSafeSegment(name) {
		sum := umfsHash([]byte(strings.TrimSpace(rawURL)))
		if len(sum) > loaderURLHashLen {
			sum = sum[:loaderURLHashLen]
		}
		name = loaderFallbackStem + "-" + sum + ext
		if !validateSafeSegment(name) {
			return "", false
		}
	}
	dest := filepath.Join(root, name)
	// 目录归属断言：无论上游串如何异常，目标都必须严格位于 TEMP 之内，
	// 不接受等于根目录本身。
	absDest, err := canonicalAbs(dest)
	if err != nil {
		return "", false
	}
	absRoot, err := canonicalAbs(root)
	if err != nil {
		return "", false
	}
	if absDest == absRoot || !PathWithinRoot(absDest, absRoot) {
		return "", false
	}
	return absDest, true
}
