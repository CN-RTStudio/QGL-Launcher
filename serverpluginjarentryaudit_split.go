package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func mpeScanJar(a *PluginJarEntryAudit, root, rel string) {
	path := filepath.Join(root, rel)
	reader, err := zip.OpenReader(path)
	if err != nil {
		a.add(rel, mpeReasonBadJar, "无法作为 ZIP/JAR 打开", false)
		return
	}
	defer reader.Close()
	if len(reader.File) > mpeMaxEntries {
		a.add(rel, mpeReasonEntryCount, fmt.Sprintf("条目数 %d 超过 %d", len(reader.File), mpeMaxEntries), false)
		return
	}
	seen := map[string]bool{}
	nested := 0
	dupCount := 0
	var dupSample string
	for _, entry := range reader.File {
		name := entry.Name
		if mpeEntryUnsafe(name) {
			a.add(rel, mpeReasonTraversal, "条目路径越界: "+name, true)
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			dupCount++
			if dupSample == "" {
				dupSample = name
			}
		}
		seen[key] = true
		if strings.HasSuffix(key, ".jar") {
			nested++
		}
		if entry.UncompressedSize64 > mpeMaxEntryBytes {
			a.add(rel, mpeReasonEntryLarge, fmt.Sprintf("条目 %s 解压后 %d 字节", name, entry.UncompressedSize64), true)
			continue
		}
		if entry.UncompressedSize64 >= mpeRatioMinBytes && entry.CompressedSize64 > 0 {
			ratio := entry.UncompressedSize64 / entry.CompressedSize64
			if ratio > mpeMaxRatio {
				a.add(rel, mpeReasonBomb, fmt.Sprintf("条目 %s 压缩比 %d", name, ratio), true)
			}
		}
	}
	if dupCount > 0 {
		a.add(rel, mpeReasonDuplicate, fmt.Sprintf("重复条目 %d 个, 首个 %s", dupCount, dupSample), false)
	}
	if nested > mpeMaxNestedJars {
		a.add(rel, mpeReasonNested, fmt.Sprintf("内嵌 JAR %d 个", nested), false)
	}
}

func mpeScanDir(a *PluginJarEntryAudit, root string) {
	dir := filepath.Join(root, "plugins")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	entries, derr := os.ReadDir(dir)
	if derr != nil {
		a.add("plugins", mpeReasonBadJar, "plugins 目录不可读", false)
		return
	}
	count := 0
	for _, entry := range entries {
		if count >= mpeMaxPlugins {
			a.add("plugins", mpeReasonEntryCount, fmt.Sprintf("已扫描 %d 个条目后截断", mpeMaxPlugins), false)
			return
		}
		count++
		name := entry.Name()
		rel := filepath.ToSlash(filepath.Join("plugins", name))
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		if len(name) > 160 {
			a.add(rel, mpeReasonBadName, "文件名超长", false)
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			a.add(rel, mpeReasonBadJar, "无法读取文件信息", false)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			a.add(rel, mpeReasonSymlink, "插件文件为符号链接", true)
			continue
		}
		if info.Size() > mpeMaxJarBytes {
			a.add(rel, mpeReasonTooLarge, fmt.Sprintf("文件体积 %d 超过上限", info.Size()), false)
			continue
		}
		a.Jars++
		mpeScanJar(a, root, rel)
	}
}

func AuditPluginJarEntries(serverDir string) *PluginJarEntryAudit {
	a := &PluginJarEntryAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", mpeReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", mpeReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", mpeReasonMissing, "服务器目录不存在", false)
		return a
	}
	mpeScanDir(a, serverDir)
	if a.Jars == 0 && len(a.Findings) == 0 {
		a.add(".", mpeReasonMissing, "未发现 plugins 目录或 JAR", false)
	}
	return a
}
