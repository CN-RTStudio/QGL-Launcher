package main

import (
	"path/filepath"
	"strings"
)

// buildLoaderDestName 由展示名、URL 与扩展名构造最终文件段名。
// 追加 URL 的 UMFS 指纹做确定性去碰撞：同一 URL 多次下载得到同一文件名（复用已
// 下载内容），不同 URL 即便展示名完全相同也会落到不同文件，且文件名不可由
// 展示名直接预测，缓解共享 TEMP 下的预置 / 覆盖面。
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

// resolveLoaderTempDest 在给定临时目录内构造加载器安装器的最终绝对落盘路径。
// 返回 ok=false 表示无法在 tempDir 内构造出安全目标（调用方应中止下载）。
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
