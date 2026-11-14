package main

import (
	"os"
	"strings"
)

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
