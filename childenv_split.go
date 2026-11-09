package main

import (
	"os"
	"strings"
)

// safePathList 构造最小安全 PATH：系统目录 + 显式附加的 Java 目录。
// javaDir 为空时只保留系统目录。结果按原顺序返回，重复项去重。
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

// buildSafeGamePATH 从进程现有 PATH 构造安全 PATH 字符串（Windows 用 ';'）。
// 返回 (安全PATH, 被丢弃条目数, 被丢弃条目列表)。
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

// sanitizeGameEnv 返回净化后的游戏进程环境（在既有环境切片上覆盖 PATH）。
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
