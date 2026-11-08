package main

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	sytMaxEntries  = 4000
	sytMaxDepth    = 6
	sytMaxFindings = 24
	sytMaxFile     = 8 * 1024 * 1024
	sytMissing     = "world-dir-missing"
	sytNotDir      = "world-dir-not-directory"
	sytLink        = "world-entry-symlink"
	sytSpecial     = "world-entry-special-file"
	sytEscape      = "world-link-escapes-root"
	sytTooDeep     = "world-entry-too-deep"
	sytTooMany     = "world-entry-limit"
	sytLockFile    = "world-lock-file-present"
	sytUnreadable  = "world-entry-unreadable"
)

type WorldSymlinkFinding struct {
	Path     string
	Reason   string
	Detail   string
	Blocking bool
}

type WorldSymlinkAudit struct {
	ServerDir string
	WorldDir  string
	Findings  []WorldSymlinkFinding
	Entries   int
}

func (a *WorldSymlinkAudit) add(path, reason, detail string, blocking bool) {
	if len(a.Findings) >= sytMaxFindings {
		return
	}
	a.Findings = append(a.Findings, WorldSymlinkFinding{Path: path, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldSymlinkAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldSymlinkFinding) bool { return f.Blocking })
}

func (a *WorldSymlinkAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WorldSymlinkAudit) Describe() string {
	return describeAuditFindings("世界存档目录未发现符号链接风险", a.Findings, 12,
		func(f WorldSymlinkFinding) []string {
			return []string{f.Reason, f.Path}
		},
		func(f WorldSymlinkFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func sytWithinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

func sytScan(root, dir string, depth int, a *WorldSymlinkAudit) {
	if depth > sytMaxDepth {
		a.add(dir, sytTooDeep, "目录层级超过上限", true)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add(dir, sytUnreadable, err.Error(), true)
		return
	}
	for _, entry := range entries {
		if a.Entries >= sytMaxEntries {
			a.add(dir, sytTooMany, "存档条目数量超过扫描上限", true)
			return
		}
		a.Entries++
		path := filepath.Join(dir, entry.Name())
		info, statErr := os.Lstat(path)
		if statErr != nil {
			a.add(path, sytUnreadable, statErr.Error(), true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			a.Entries++
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil {
				a.add(path, sytLink, "无法解析链接目标", true)
				continue
			}
			if !sytWithinRoot(root, resolved) {
				a.add(path, sytEscape, "链接指向存档根目录之外", true)
				continue
			}
			a.add(path, sytLink, "存档内存在符号链接", false)
			continue
		}
		if info.IsDir() {
			sytScan(root, path, depth+1, a)
			continue
		}
		if !info.Mode().IsRegular() {
			a.add(path, sytSpecial, "存档内存在设备、管道或套接字文件", true)
		}
		continue
	}
}

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
	info, err := os.Stat(worldDir)
	if os.IsNotExist(err) {
		a.add(worldDir, sytMissing, "世界存档目录不存在", false)
		return a
	}
	if err != nil {
		a.add(worldDir, sytUnreadable, err.Error(), true)
		return a
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
