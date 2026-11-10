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
func splitWindowsDrive(p string) (root, rest string) {
	if len(p) >= 2 && p[1] == ':' {
		return p[:2], p[2:]
	}
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		segs := strings.Split(strings.TrimLeft(p, `\/`), `\/`)
		if len(segs) >= 3 {
			return `\\` + segs[0] + `\` + segs[1] + `\`, strings.Join(segs[2:], `\`)
		}
		return `\\` + strings.Join(segs, `\`), ""
	}
	if strings.HasPrefix(p, `/`) || strings.HasPrefix(p, `\`) {
		// Unix 风格绝对路径：整条视为 root，供测试与类 Unix 平台复用。
		return "", ""
	}
	return "", ""
}

func safePathList(systemEntries []string, javaDir string) []string {
	seen := make(map[string]bool, len(systemEntries)+1)
	var out []string
	appendEntry := func(e string) {
		key := strings.ToLower(strings.TrimRight(strings.TrimSpace(strings.Trim(e, `"'`)), `\/`))
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, e)
	}
	for _, e := range systemEntries {
		if isSystemDirEntry(e) {
			appendEntry(strings.TrimSpace(e))
		}
	}
	if javaDir != "" {
		appendEntry(javaDir)
	}
	return out
}
func buildSafeGamePATH(currentPath string, javaDir string) (string, int, []string) {
	entries := strings.Split(currentPath, pathSep)
	kept := safePathList(entries, javaDir)
	dropped := 0
	var droppedList []string
	for _, e := range entries {
		t := strings.TrimSpace(strings.Trim(e, `"'`))
		if t == "" {
			continue
		}
		if !isSystemDirEntry(t) && !strings.EqualFold(strings.TrimRight(strings.TrimSpace(t), `\/`), strings.TrimRight(strings.TrimSpace(javaDir), `\/`)) {
			dropped++
			if len(droppedList) < 10 {
				droppedList = append(droppedList, t)
			}
		}
	}
	return strings.Join(kept, pathSep), dropped, droppedList
}

func sanitizeGameEnv(env []string, javaDir string) ([]string, int, []string) {
	var safePath string
	var dropped int
	var droppedList []string
	for _, kv := range env {
		if strings.HasPrefix(strings.ToUpper(kv), "PATH=") {
			cur := kv[len("PATH="):]
			safePath, dropped, droppedList = buildSafeGamePATH(cur, javaDir)
			break
		}
	}
	if safePath == "" {
		// 环境里没有 PATH（理论上不该发生）→ 用系统 PATH 净化兜底。
		safePath, dropped, droppedList = buildSafeGamePATH(os.Getenv("PATH"), javaDir)
	}
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, kv := range env {
		if strings.HasPrefix(strings.ToUpper(kv), "PATH=") {
			out = append(out, "PATH="+safePath)
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, "PATH="+safePath)
	}
	return out, dropped, droppedList
}
