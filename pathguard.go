package main

// pathguard.go —— 路径归属（containment）判定的共享安全内核。
//
// 启动器会把大量“来自外部清单 / 压缩包 / 环境变量”的路径拼到真实文件系统上：
// 解压目标、natives 目录、libraries jar、以及最终要 exec 的 java 可执行文件。
// 历史上这些检查分散在各文件里、各写一份 filepath.Abs + HasPrefix，容易漏判
// 两类问题：
//   1. 词法逃逸：".."、盘符、相对路径拼出 root 之外（Zip Slip）；
//   2. 符号链接逃逸：词法上在 root 内，但其中某一级目录/文件是指向 root 之外
//      的符号链接 / junction（Windows），写入或执行会“顺着链接”落到外部。
//
// 这里提供唯一的判定实现：词法归属 PathWithinRoot，和解析真实路径后的归属
// ResolvedPathWithinRoot，供解压与可执行文件信任复用，配单元测试。

import (
	"os"
	"path/filepath"
	"strings"
)

// canonicalAbs 返回去掉结尾分隔符（根目录自身除外）的干净绝对路径，
// 保证 HasPrefix 比较不会被 "/a/b" 误判成 "/a/bc" 这类兄弟目录。
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

// PathWithinRoot 做纯词法（不触碰文件系统）的归属判定：child 必须等于 root
// 或位于 root 之内。两者都会先转成干净绝对路径。
func PathWithinRoot(child, root string) bool {
	absRoot, err := canonicalAbs(root)
	if err != nil {
		return false
	}
	absChild, err := canonicalAbs(child)
	if err != nil {
		return false
	}
	if absChild == absRoot {
		return true
	}
	return strings.HasPrefix(absChild, absRoot+string(os.PathSeparator))
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
		if realChild == realRoot {
			return realChild, true
		}
		return realChild, strings.HasPrefix(realChild, realRoot+string(os.PathSeparator))
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
		return lexChild, strings.HasPrefix(lexChild, realRoot+string(os.PathSeparator)) ||
			lexChild == realRoot
	}
	realParent, err = canonicalAbs(realParent)
	if err != nil {
		return "", false
	}
	if realParent != realRoot &&
		!strings.HasPrefix(realParent, realRoot+string(os.PathSeparator)) {
		return "", false
	}
	lexChild, err := canonicalAbs(child)
	if err != nil {
		return "", false
	}
	return lexChild, PathWithinRoot(lexChild, realRoot)
}

// safeRelChar 是外部清单里“相对路径单段”允许出现的字符白名单。
// 只放行 Maven 坐标 / 资源索引 ID 真实会用到的字符，其余（分隔符、盘符冒号、
// 通配符、管道、引号、控制字符等）一律拒绝，从源头掐断盘符、ADS 与参数注入。
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

// validateSafeSegment 校验单个路径段：非空、非 "."/".."、不含 Windows
// 保留设备名（CON/PRN/AUX/NUL/COMx/LPTx）、结尾不留空格或点。
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

// SafeMavenRelPath 校验外部清单给出的“正斜杠相对路径”（Maven library path、
// assetIndex id 等），返回归一化后的安全相对路径；不合法返回空串。
// 与 isSafeRelPath 的差别：后者只做 Clean/.. 排除，这里走严格字符白名单，
// 并拒绝反斜杠、冒号、盘符、绝对路径与保留设备名。
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

// SafeSimpleName 校验不含任何分隔符的单段名字（资源索引 ID、版本号等），
// 防止把 "a/b" 或 "../x" 当作一个文件名片段拼接。
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

// SafeMojmapsMappingsPath 由不受信任的版本 JSON 中 data.MOJMAPS.client 值
// （形如 "group:artifact:version@txt"）推导官方 mappings 的落盘绝对路径。
// group 各段、artifact、version 全部走 SafeSimpleName 严格白名单，扩展名只允许
// 短小的小写字母数字，并最终用 PathWithinRoot 约束结果必须仍在 <mcDir>/libraries
// 之下，防止恶意安装器借 ".." 段、分隔符或带穿越的扩展名把文件写到 libraries 之外。
// 任一环节不合法都返回 ok=false（调用方按“跳过 mappings”处理，不影响启动）。
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
