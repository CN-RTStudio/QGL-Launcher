package main

// modlocation.go —— “受管 Mod 文件”归属判定的共享安全内核。
//
// ToggleMod / DeleteMod 接收的是渲染层传来的完整路径。历史上只用 PathWithin(mcDir)
// 兜底，范围等于整个 .minecraft：一旦渲染层被 XSS / 注入，或前端自身拼错路径，就可以
//   - 把 libraries / versions 里的任意 .jar 改名为 .jar.disabled（破坏依赖、DoS）；
//   - 删除 saves 世界、版本 JSON、配置等 .minecraft 内任意文件。
//
// 启动器真正“管理”的 Mod 只有两类目录的顶层文件：
//   - 全局：<mcDir>/mods/<file>
//   - 版本隔离：<mcDir>/versions/<version>/mods/<file>
// 且文件只能是 .jar / .jar.disabled（GetModList 列出的也只有这两种）。
// 本文件只做纯词法判定（不触碰文件系统），配单元测试，供 Toggle/Delete 共用，
// 避免两处各写一份前缀判断再次漏判。

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	modsDirSegment   = "mods"
	versionsSegment  = "versions"
	disabledJarSuffix = ".jar.disabled"
	jarSuffix         = ".jar"
)

// modNameLooksSafe 校验 Mod 文件名本身：非空、单段名（不含分隔符；调用方已按
// os.PathSeparator 切分，这里再兜一次正斜杠）、不含 NUL/控制字符、不是 "."/".."，
// 且结尾不是 Win32 会吞掉的点或空格。
func modNameLooksSafe(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 || name[i] < 0x20 {
			return false
		}
	}
	return true
}

// isModJarName 报告文件名是否为受管的 jar（启用）或已禁用 jar（.jar.disabled）。
// 扩展名大小写不敏感，与 GetModList / ToggleMod 的既有口径一致。
func isModJarName(name string) bool {
	if !modNameLooksSafe(name) {
		return false
	}
	lower := strings.ToLower(name)
	// ".jar" 与 ".jar.disabled" 两种后缀互斥（后者结尾是 ".disabled"）。
	return strings.HasSuffix(lower, jarSuffix) || strings.HasSuffix(lower, disabledJarSuffix)
}

// resolveManagedModPath 判定 p 是否为某个“受管 mods 目录”的顶层 jar 文件。
// 返回 canonicalAbs 归一化后的绝对路径；不满足布局 / 扩展名 / 归属时 ok=false。
//
// 仅接受精确布局（Clean 已折叠 ".."，再用 PathWithinRoot 双保险）：
//
//	<mcDir>/mods/<file>                       -> segs = [mods, file]
//	<mcDir>/versions/<version>/mods/<file>    -> segs = [versions, version, mods, file]
//
// mods 子目录（mods/sub/x.jar）、libraries、saves 等一律不算受管文件。
func resolveManagedModPath(mcDir, p string) (string, bool) {
	// 预检原始文件名段（尚未经过 Windows 路径归一化）：尾部点 / 空格 / 控制字符等
	// 会被 OS 层 Abs/Clean 静默剥离或折叠，导致 "a.jar " 归一化后冒充合法受管文件。
	// 这里在归一化之前就用 modNameLooksSafe 拦截，保持与 modNameLooksSafe 的
	// “Win32 会吞掉的点 / 空格结尾一律不受管”口径一致。
	rawBase := p
	if trimmed := strings.TrimRight(p, `\/`); trimmed != "" {
		rawBase = filepath.Base(trimmed)
	}
	if !modNameLooksSafe(rawBase) {
		return "", false
	}

	root, err := canonicalAbs(mcDir)
	if err != nil {
		return "", false
	}
	abs, err := canonicalAbs(p)
	if err != nil {
		return "", false
	}
	// 先做整体归属：任何落在 .minecraft 之外（盘符逃逸 / Clean 后仍越界）的直接拒绝。
	if !PathWithinRoot(abs, root) {
		return "", false
	}
	if abs == root {
		return "", false
	}
	rel := abs[len(root)+1:]
	segs := strings.Split(rel, string(os.PathSeparator))

	var fileName string
	switch {
	case len(segs) == 2 && strings.EqualFold(segs[0], modsDirSegment):
		// 全局 mods 目录顶层文件。
		fileName = segs[1]
	case len(segs) == 4 && strings.EqualFold(segs[0], versionsSegment) &&
		strings.EqualFold(segs[2], modsDirSegment) && safeVersionSegment(segs[1]):
		// 版本隔离 mods 目录；版本段必须是真实单段名（Clean 已折叠 ".."，
		// safeVersionSegment 再排除空段 / "." / 分隔符），防止 versions/../mods 触底。
		fileName = segs[3]
	default:
		return "", false
	}

	if !isModJarName(fileName) {
		return "", false
	}
	return abs, true
}

// safeVersionSegment 校验隔离布局中的版本目录段：Clean 已折叠 ".."，这里再排除
// 空段、"."/".." 与任何分隔符，避免 versions/../mods 之类畸形拼接触底。
func safeVersionSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	return !strings.ContainsAny(seg, `/\`)
}

// resolveManagedModsDir 判定 p 是否为某个“受管 mods 目录”本身（用于下载落盘目录
// 校验）。接受精确布局：
//
//	<mcDir>/mods                    -> segs = [mods]
//	<mcDir>/versions/<v>/mods       -> segs = [versions, v, mods]
//
// mods 目录的上级、libraries、saves、mcDir 根等一律拒绝：下载队列的保存目录只能由
// 程序按版本隔离策略决定，不能由渲染层指到 .minecraft 内任意位置投放 jar。
func resolveManagedModsDir(mcDir, p string) (string, bool) {
	root, err := canonicalAbs(mcDir)
	if err != nil {
		return "", false
	}
	abs, err := canonicalAbs(p)
	if err != nil {
		return "", false
	}
	if !PathWithinRoot(abs, root) || abs == root {
		return "", false
	}
	rel := abs[len(root)+1:]
	segs := strings.Split(rel, string(os.PathSeparator))

	switch {
	case len(segs) == 1 && strings.EqualFold(segs[0], modsDirSegment):
		return abs, true
	case len(segs) == 3 && strings.EqualFold(segs[0], versionsSegment) &&
		strings.EqualFold(segs[2], modsDirSegment) && safeVersionSegment(segs[1]):
		return abs, true
	default:
		return "", false
	}
}

// sameManagedModDir 报告 rename 的源与目标是否归一化后位于同一个受管 mods 目录，
// 防止借改名把 jar 移出 / 移入非受管目录（源、目标都必须是受管 jar，且父目录相同）。
func sameManagedModDir(fromAbs, toAbs string) bool {
	fromDir := filepath.Dir(fromAbs)
	toDir := filepath.Dir(toAbs)
	return fromDir == toDir
}
