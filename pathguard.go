package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func canonicalAbs(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", os.ErrInvalid
	}
	a, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	// Windows 卷名大小写归一（C:\ 与 c:\）。
	if vol := filepath.VolumeName(a); vol != "" {
		a = strings.ToUpper(vol) + a[len(vol):]
	}
	return a, nil
}
func PathWithinRoot(child, root string) bool {
	return pathWithinRootMode(child, root, runtime.GOOS == "windows")
}

func pathWithinRootMode(child, root string, fold bool) bool {
	absRoot, err := canonicalAbs(root)
	if err != nil {
		return false
	}
	absChild, err := canonicalAbs(child)
	if err != nil {
		return false
	}
	rootKey := pathCompareKey(absRoot, fold)
	childKey := pathCompareKey(absChild, fold)
	if childKey == rootKey {
		return true
	}
	return strings.HasPrefix(childKey, rootKey+string(os.PathSeparator))
}

func pathCompareKey(p string, fold bool) string {
	if fold {
		return strings.ToLower(p)
	}
	return p
}

func safeRelChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	switch r {
	case '.', '_', '-', '+', '~':
		return true
	}
	return false
}
func validateSafeSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	for _, r := range seg {
		if !safeRelChar(r) {
			return false
		}
	}
	// Windows 资源管理器 / Win32 会吞掉结尾的点和空格，可能造成同名绕过。
	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		return false
	}
	upper := strings.ToUpper(seg)
	if dot := strings.IndexByte(upper, '.'); dot >= 0 {
		upper = upper[:dot]
	}
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return false
	}
	if len(upper) == 4 {
		p := upper[:3]
		if (p == "COM" || p == "LPT") && upper[3] >= '1' && upper[3] <= '9' {
			return false
		}
	}
	return true
}

func SafeMavenRelPath(name string) string {
	if name == "" || len(name) > 1024 {
		return ""
	}
	for _, r := range name {
		if r == 0 || r < 0x20 {
			return ""
		}
	}
	if strings.ContainsRune(name, '\\') || strings.ContainsRune(name, ':') ||
		strings.HasPrefix(name, "/") {
		return ""
	}
	var segs []string
	for _, seg := range strings.Split(name, "/") {
		if !validateSafeSegment(seg) {
			return ""
		}
		segs = append(segs, seg)
	}
	if len(segs) == 0 {
		return ""
	}
	return strings.Join(segs, "/")
}

func SafeSimpleName(name string) string {
	if name == "" || len(name) > 256 {
		return ""
	}
	if strings.ContainsAny(name, `/\`) {
		return ""
	}
	if !validateSafeSegment(name) {
		return ""
	}
	return name
}
func SafeMojmapsMappingsPath(mcDir, coord, ext string) (string, bool) {
	parts := strings.Split(coord, ":")
	if len(parts) != 3 {
		return "", false
	}
	groupSegs := strings.Split(parts[0], ".")
	if len(groupSegs) == 0 {
		return "", false
	}
	relElems := make([]string, 0, len(groupSegs)+4)
	relElems = append(relElems, "libraries")
	for _, g := range groupSegs {
		gs := SafeSimpleName(g)
		if gs == "" {
			return "", false
		}
		relElems = append(relElems, gs)
	}
	artifact := SafeSimpleName(parts[1])
	version := SafeSimpleName(parts[2])
	if artifact == "" || version == "" {
		return "", false
	}
	if !safeMappingsExt(ext) {
		return "", false
	}
	relElems = append(relElems, artifact, version, artifact+"-"+version+"-mappings."+ext)
	target := filepath.Join(mcDir, filepath.Join(relElems...))
	if !PathWithinRoot(target, filepath.Join(mcDir, "libraries")) {
		return "", false
	}
	return target, true
}

func SafeMappingsVersionPath(mcDir, version string) (string, bool) {
	v := SafeSimpleName(version)
	if v == "" {
		return "", false
	}
	target := filepath.Join(mcDir, "libraries", "net", "minecraft", "client", v,
		"client-"+v+"-mappings.txt")
	if !PathWithinRoot(target, filepath.Join(mcDir, "libraries")) {
		return "", false
	}
	return target, true
}

// safeMappingsExt 限制 mappings 扩展名只能是不超过 8 个字符的小写字母数字（官方为 txt）。
func safeMappingsExt(ext string) bool {
	if ext == "" || len(ext) > 8 {
		return false
	}
	for i := 0; i < len(ext); i++ {
		c := ext[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// IsLowerHex 报告 s 是否恰好是 n 个小写十六进制字符（用于校验外部 SHA1 等哈希）。
func IsLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ResolvedPathWithinRoot 先解析 root 与 child 的真实路径（跟随符号链接 /
// junction），再判定真实 child 是否仍在真实 root 之内。
//
// 行为约定：
//   - root 必须已存在（要执行/写入的受信根目录必然存在），解析失败视为不通过；
//   - child 已存在时按真实路径判定，能挡住“链接落在 root 内、目标在 root 外”；
//   - child 尚不存在（如解压前预校验目标）时退回词法判定，但要求其父目录的
//     真实路径仍在 root 内，避免新建名本身借父目录链接逃逸。
//
// 返回归一化后的真实 child 路径（供调用方记录 / 使用）。
func ResolvedPathWithinRoot(child, root string) (string, bool) {
	return resolvedPathWithinRootMode(child, root, runtime.GOOS == "windows")
}

func resolvedPathWithinRootMode(child, root string, fold bool) (string, bool) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	realRoot, err = canonicalAbs(realRoot)
	if err != nil {
		return "", false
	}

	if _, statErr := os.Lstat(child); statErr == nil {
		realChild, err := filepath.EvalSymlinks(child)
		if err != nil {
			return "", false
		}
		realChild, err = canonicalAbs(realChild)
		if err != nil {
			return "", false
		}
		return realChild, pathWithinRootMode(realChild, realRoot, fold)
	}

	// child 尚不存在：用词法 child 与“已解析的真实父目录”双重确认。
	parent := filepath.Dir(child)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		// 父目录也不存在，无法用真实路径背书，退化为纯词法判定（保守但可用）。
		lexChild, e := canonicalAbs(child)
		if e != nil {
			return "", false
		}
		return lexChild, pathWithinRootMode(lexChild, realRoot, fold)
	}
	realParent, err = canonicalAbs(realParent)
	if err != nil {
		return "", false
	}
	if !pathWithinRootMode(realParent, realRoot, fold) {
		return "", false
	}
	lexChild, err := canonicalAbs(child)
	if err != nil {
		return "", false
	}
	return lexChild, pathWithinRootMode(lexChild, realRoot, fold)
}
