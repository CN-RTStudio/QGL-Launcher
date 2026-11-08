package main

// loaderdest.go —— 加载器（Forge / NeoForge / OptiFine）安装器临时落盘目标名的
// 纯词法构造内核。
//
// 威胁模型：
//   downloadLoaderItem 会把第三方安装器下载到系统 TEMP，且当它是 .jar 时立刻
//   "下载即运行"（java -jar），属于本机最高危的一条链。旧实现的临时文件名直接
//   取 item.CustomName：
//     1. CustomName 是给人看的展示串（形如 "forge 47.2.0 (1.20.1)"），含空格、
//        括号等字符，未做任何文件名白名单；
//     2. 扩展名用 strings.HasSuffix(原始 URL, ".jar") 判定，URL 带 query
//        （x.jar?token=...）时会漏判；
//     3. 文件名在共享 TEMP 里可预测，不同加载器 / 不同 URL 只要展示名相同就落到
//        同一个文件，存在互相覆盖、被同机其它进程预置占位的碰撞面；
//     4. 没有校验最终文件段是否为 Windows 保留设备名（CON / PRN / COM1 等），
//        也没有断言拼接结果确实仍在 TEMP 之内。
//
// 本内核只做纯计算、不触碰文件系统，便于穷举单测：
//   - loaderArtifactExt：解析 URL 的 path 部分判定 .jar/.exe（忽略 query）；
//   - sanitizeLoaderSlug：把任意展示串收敛成文件名安全的短 slug；
//   - buildLoaderDestName：slug + URL 的 UMFS 指纹 + 扩展名，去碰撞且不可预测；
//   - resolveLoaderTempDest：再走 validateSafeSegment 保留设备名收口与
//     PathWithinRoot 目录归属断言，产出最终绝对路径。

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
//         被资源管理器吞掉造成同名绕过；
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
