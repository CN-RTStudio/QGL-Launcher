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

func AuditModJarManifests(serverDir string) *ModJarManifestAudit {
	a := &ModJarManifestAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", mjmReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", mjmReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", mjmReasonMissing, "服务器目录不存在", false)
		return a
	}
	mjmScanDir(a, serverDir)
	if a.Jars == 0 && len(a.Findings) == 0 {
		a.add(".", mjmReasonMissing, "未发现 mods 目录或 JAR", false)
	}
	return a
}
