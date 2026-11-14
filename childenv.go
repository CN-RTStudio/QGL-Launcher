package main

import (
	"os"
	"path/filepath"
	"strings"
)

// pathSep 是 Windows PATH 分隔符（同时兼容 Unix 冒号以便测试复用）。
const pathSep = string(os.PathListSeparator)

// isSystemDirEntry 判断 PATH 条目是否为系统保留目录（大小写不敏感）：
//   - Windows 目录本身（C:\Windows）
//   - System32 / SysWOW64（含子路径，如 C:\Windows\System32\WindowsPowerShell\v1.0）
//   - 系统根的 System32（理论极少见，防 CD 版系统）
func isSystemDirEntry(entry string) bool {
	p := strings.TrimSpace(entry)
	p = strings.Trim(p, `"'`)
	if p == "" {
		return false
	}
	lower := strings.ToLower(p)
	lower = strings.TrimRight(lower, `\/`)

	// 必须绝对路径且含盘符或 UNC 前缀，相对路径 / 裸目录名一律不信任。
	if !filepath.IsAbs(p) {
		return false
	}

	root, rest := splitWindowsDrive(lower)
	if root == "" {
		return false
	}
	rest = strings.TrimLeft(rest, `\/`)
	if rest == "" {
		// 裸盘根（C:\）不是系统目录，放行会引入整盘可写面。
		return false
	}

	// C:\Windows 本身。
	if strings.EqualFold(rest, "windows") {
		return true
	}
	// C:\Windows\System32 及其子目录；SysWOW64 同理。
	if segs := strings.Split(rest, `\`); len(segs) >= 2 && strings.EqualFold(segs[0], "windows") {
		second := strings.ToLower(segs[1])
		return second == "system32" || second == "syswow64"
	}
	return false
}

// splitWindowsDrive 把路径拆成盘符/UNC 前缀与其余部分；非 Windows 盘符路径
// 返回空 root（此时绝对路径 / 与 \ 均可，测试友好）。
