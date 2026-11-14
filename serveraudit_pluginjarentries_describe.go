package main

import (
	"archive/zip"
	"fmt"
	"path/filepath"
	"strings"
)

func (a *PluginJarEntryAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginJarEntryFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func mpeEntryUnsafe(name string) bool {
	if name == "" {
		return true
	}
	if strings.ContainsAny(name, "\x00\n\r") {
		return true
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
		return true
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return true
	}
	if len(name) > 1 && name[1] == ':' {
		return true
	}
	if strings.Contains(name, "\\") {
		return true
	}
	trimmed := strings.TrimPrefix(lower, "./")
	if strings.HasPrefix(trimmed, "../") {
		return true
	}
	return false
}

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
