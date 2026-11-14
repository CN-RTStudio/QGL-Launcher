package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func mjmScanDir(a *ModJarManifestAudit, root string) {
	dir := filepath.Join(root, "mods")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		a.add("mods", mjmReasonBadJar, "mods 目录不可读", false)
		return
	}
	count := 0
	for _, entry := range entries {
		if count >= mjmMaxMods {
			a.add("mods", mjmReasonEntryOverflow, fmt.Sprintf("已扫描 %d 个条目后截断", mjmMaxMods), false)
			return
		}
		count++
		name := entry.Name()
		rel := filepath.ToSlash(filepath.Join("mods", name))
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		if len(name) > 160 {
			a.add(rel, mjmReasonBadName, "文件名超长", false)
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			a.add(rel, mjmReasonBadJar, "无法读取文件信息", false)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			a.add(rel, mjmReasonSymlink, "模组文件为符号链接", true)
			continue
		}
		if info.Size() > mjmMaxJarBytes {
			a.add(rel, mjmReasonTooLarge, fmt.Sprintf("文件体积 %d 超过上限", info.Size()), false)
			continue
		}
		a.Jars++
		mjmScanJar(a, root, rel, info.Size())
	}
}

func runJarRootAudit(serverDir, reasonMissing, reasonSymlink, emptyHint string,
	add func(file, reason, detail string, blocking bool),
	scan func(dir string),
	jars func() int,
	findingsLen func() int) {
	if serverDir == "" {
		add(".", reasonMissing, "未配置服务器目录", false)
		return
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		add(".", reasonSymlink, "服务器目录为符号链接", true)
		return
	}
	if _, err := os.Stat(serverDir); err != nil {
		add(".", reasonMissing, "服务器目录不存在", false)
		return
	}
	scan(serverDir)
	if jars() == 0 && findingsLen() == 0 {
		add(".", reasonMissing, emptyHint, false)
	}
}

func AuditModJarManifests(serverDir string) *ModJarManifestAudit {
	a := &ModJarManifestAudit{ServerDir: serverDir}
	runJarRootAudit(serverDir, mjmReasonMissing, mjmReasonSymlink, "未发现 mods 目录或 JAR",
		func(file, reason, detail string, blocking bool) { a.add(file, reason, detail, blocking) },
		func(dir string) { mjmScanDir(a, dir) },
		func() int { return a.Jars },
		func() int { return len(a.Findings) })
	return a
}

func mjmClassPathEntries(value string) []string {
	items := make([]string, 0, 8)
	for _, raw := range strings.Split(value, " ") {
		for _, piece := range strings.Split(raw, ",") {
			trimmed := strings.TrimSpace(piece)
			if trimmed != "" {
				items = append(items, trimmed)
			}
		}
	}
	return items
}

func mjmUnsafeClassPathEntry(entry string) bool {
	lower := strings.ToLower(entry)
	if strings.Contains(lower, "..") {
		return true
	}
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "http") || strings.HasPrefix(lower, "file:") {
		return true
	}
	if strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, "\\") {
		return true
	}
	if len(entry) > 2 && entry[1] == ':' {
		return true
	}
	if strings.ContainsAny(entry, "\x00\n\r") {
		return true
	}
	return false
}

func (a *ModJarManifestAudit) Describe() string {
	return describeFindings(a.Findings, func(f ModJarFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}
