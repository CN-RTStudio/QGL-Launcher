package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pjcMaxFindings = 14
	pjcMaxJars     = 512
	pjcMaxJarSize  = 256 * 1024 * 1024
	pjcMaxEntries  = 20000
	pjcMiss        = "plugin-dir-missing"
	pjcRead        = "plugin-dir-unreadable"
	pjcLink        = "plugin-dir-symlink"
	pjcJarLink     = "plugin-jar-symlink"
	pjcJarOpen     = "plugin-jar-unreadable"
	pjcJarSize     = "plugin-jar-oversized"
	pjcCaseClash   = "plugin-entry-case-clash"
	pjcDuplicate   = "plugin-entry-duplicate"
	pjcBackslash   = "plugin-entry-backslash"
	pjcCtrlReason  = "plugin-entry-control-char"
)

type PjcFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type PjcAudit struct {
	ServerDir string
	Jars      int
	Entries   int
	Findings  []PjcFinding
}

func (a *PjcAudit) add(jar, entry, reason, detail string, blocking bool) {
	if len(a.Findings) >= pjcMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PjcFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PjcAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PjcAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PjcAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件条目命名无冲突，%d 个 jar，共 %d 个条目", a.Jars, a.Entries)
	}
	sorted := make([]PjcFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Entry < sorted[j].Entry
	})
	parts := make([]string, 0, len(sorted))
	for i, f := range sorted {
		if i >= 8 {
			parts = append(parts, fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		parts = append(parts, f.Reason)
	}
	return strings.Join(parts, "；")
}

func pjcHasCtrlChar(name string) bool {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func AuditPluginEntryCase(serverDir string) *PjcAudit {
	a := &PjcAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("plugins", "", pjcMiss, "未配置服务器目录", false)
		return a
	}

	dir := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		a.add("plugins", "", pjcMiss, "缺少插件目录", false)
		return a
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("plugins", "", pjcRead, err.Error(), true)
		return a
	}
	if link {
		a.add("plugins", "", pjcLink, "插件目录是符号链接或特殊文件", true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("plugins", "", pjcRead, "无法读取插件目录", true)
		return a
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		a.Jars++
		path := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(path)
		if err != nil {
			a.add(name, "", pjcJarOpen, err.Error(), true)
			continue
		}
		if link {
			a.add(name, "", pjcJarLink, "jar 是符号链接或特殊文件", true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, "", pjcJarOpen, "jar 无法访问", true)
			continue
		}
		if info.Size() > pjcMaxJarSize {
			a.add(name, "", pjcJarSize, fmt.Sprintf("jar %d 字节超过上限", info.Size()), false)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			a.add(name, "", pjcJarOpen, "jar 不是合法 zip", true)
			continue
		}

		seenLower := make(map[string]string, len(archive.File))
		seenExact := make(map[string]int, len(archive.File))
		count := 0
		for _, file := range archive.File {
			if count >= pjcMaxEntries {
				break
			}
			count++
			a.Entries++
			entryName := file.Name
			lower := strings.ToLower(entryName)
			seenExact[entryName]++
			if prev, ok := seenLower[lower]; ok && prev != entryName {
				a.add(name, entryName, pjcCaseClash, "与条目 "+prev+" 仅大小写不同", true)
			} else {
				seenLower[lower] = entryName
			}
			if seenExact[entryName] == 2 {
				a.add(name, entryName, pjcDuplicate, "同名条目重复出现", true)
			}
			if strings.Contains(entryName, "\\") {
				a.add(name, entryName, pjcBackslash, "条目名含反斜杠", false)
			}
			if pjcHasCtrlChar(entryName) {
				a.add(name, entryName, pjcCtrlReason, "条目名含控制字符", true)
			}
		}
		archive.Close()
	}

	if a.Jars > pjcMaxJars {
		a.add("plugins", "", pjcCaseClash, fmt.Sprintf("jar 数量 %d 超过上限", a.Jars), false)
	}
	return a
}
