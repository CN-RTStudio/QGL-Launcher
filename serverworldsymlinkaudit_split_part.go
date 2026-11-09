package main

import (
	"os"
	"path/filepath"
	"strings"
)

func AuditServerWorldSymlinks(serverDir string) *WorldSymlinkAudit {
	a := &WorldSymlinkAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("", sytMissing, "未配置服务器目录", true)
		return a
	}
	levelName := "world"
	propsPath := filepath.Join(serverDir, "server.properties")
	if data, err := readBoundedFile(propsPath, sytMaxFile); err == nil {
		if props := pxParseProperties(string(data)); props != nil {
			if raw, ok := props["level-name"]; ok {
				candidate := strings.TrimSpace(cfgStripQuotes(raw))
				if candidate != "" && !strings.ContainsAny(candidate, "/\\") && candidate != "." && candidate != ".." {
					levelName = candidate
				}
			}
		}
	}
	worldDir := filepath.Join(serverDir, levelName)
	a.WorldDir = worldDir
	info, err := os.Lstat(worldDir)
	if os.IsNotExist(err) {
		a.add(worldDir, sytMissing, "世界存档目录不存在", false)
		return a
	}
	if err != nil {
		a.add(worldDir, sytUnreadable, err.Error(), true)
		return a
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := filepath.EvalSymlinks(worldDir)
		if resolveErr != nil {
			a.add(worldDir, sytLink, "无法解析世界目录链接目标", true)
			return a
		}
		if !sytWithinRoot(serverDir, resolved) {
			a.add(worldDir, sytEscape, "世界目录是符号链接且指向服务器目录之外", true)
			return a
		}
		a.add(worldDir, sytLink, "世界目录是符号链接（指向服务器目录内）", false)
		worldDir = resolved
		a.WorldDir = resolved
		linked, linkErr := os.Lstat(resolved)
		if linkErr != nil {
			a.add(resolved, sytUnreadable, linkErr.Error(), true)
			return a
		}
		info = linked
	}
	if !info.IsDir() {
		a.add(worldDir, sytNotDir, "世界存档路径不是目录", true)
		return a
	}
	lockPath := filepath.Join(worldDir, "session.lock")
	if _, lockErr := os.Stat(lockPath); lockErr == nil {
		a.add(lockPath, sytLockFile, "存档仍存在 session.lock，可能被占用", false)
	}
	sytScan(worldDir, worldDir, 0, a)
	return a
}
