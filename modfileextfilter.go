package main

// modfileextfilter.go —— mods 目录文件扩展名白名单。
//
// 玩家把 .exe / .bat / .dll / .js 直接丢进 mods 目录的事并不少见；虽然 MC
// 加载器只认 .jar，但这些孤儿文件会被病毒扫描当成可疑物，也会被某些启动器
// 误当成资源。这里把“mods 目录里这个文件该不该被当成 mod 处理”收敛成纯函数。
//
// 不删除文件，只决定是否纳入审计/加载清单。

import (
	"path/filepath"
	"strings"
)

// 允许作为 mod 候选的扩展名（小写，带点）。
var allowedModExts = []string{".jar", ".jar.disabled", ".zip"}

// 是否应当跳过这个 mods 目录条目。
func IsModCandidate(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if base == "" || strings.HasPrefix(base, ".") {
		// 隐藏文件/点文件（.DS_Store、.gitkeep）不是 mod。
		return false
	}
	for _, ext := range allowedModExts {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// FilterModCandidates 从文件名列表里挑出 mod 候选。
func FilterModCandidates(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if IsModCandidate(n) {
			out = append(out, n)
		}
	}
	return out
}

// BlockedModExtReason 返回被拒原因（用于日志/提示）。
func BlockedModExtReason(name string) string {
	if IsModCandidate(name) {
		return ""
	}
	return "extension-not-allowed-or-hidden-file"
}
