package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// AuditGameClasspath 对游戏主 classpath 做最终验收：数量有界、逐条强制校验（绝对 .jar、
// 无 UNC/穿越/控制符、必须落在 roots 内），并去重。任一“危险条目”出现都记 critical；
// SafeEntries 只保留安全且去重后的条目，调用方可据此重建干净 classpath。
func AuditGameClasspath(entries []string, roots []string) *GameClasspathAudit {
	g := &GameClasspathAudit{}
	if len(entries) > maxGameClasspathEntries {
		g.add("gcp-too-many", launchSeverityCritical, "classpath",
			fmt.Sprintf("classpath 条目数 %d 超过上限 %d", len(entries), maxGameClasspathEntries))
	}
	seen := make(map[string]struct{}, len(entries))
	dupCount := 0
	for i, entry := range entries {
		field := fmt.Sprintf("classpath[%d]", i)
		if code := classifyGameClasspathEntry(entry, roots); code != "" {
			g.add(code, launchSeverityCritical, field, "不安全的 classpath 条目: "+code)
			g.Rejected++
			continue
		}
		key := strings.ToLower(filepath.Clean(entry))
		if _, ok := seen[key]; ok {
			dupCount++
			continue // 重复条目不再次加入，但也不算危险（仅统计去重）
		}
		seen[key] = struct{}{}
		g.SafeEntries = append(g.SafeEntries, entry)
	}
	if dupCount > 0 {
		g.add("gcp-duplicate", launchSeverityWarn, "classpath",
			fmt.Sprintf("classpath 含 %d 条重复条目（已去重）", dupCount))
	}
	if len(g.SafeEntries) == 0 {
		g.add("gcp-all-rejected", launchSeverityCritical, "classpath", "没有任何安全可用的 classpath 条目")
	}
	return g
}

// AuditGameLocalPaths 审计游戏本地路径：natives 目录（java.library.path /
// lwjgl.librarypath）与 libraries 目录必须绝对、有界、无 UNC/穿越/控制符，且落在
// 允许根（.minecraft）内。防止被篡改进程把本地库搜索目录指到外部攻击者目录。
func AuditGameLocalPaths(nativesDir, librariesDir, assetsDir string, roots []string) *LaunchAudit {
	a := &LaunchAudit{}
	check := func(label, p string) {
		if strings.TrimSpace(p) == "" {
			a.add("localpath-empty", launchSeverityCritical, label, "本地路径为空")
			return
		}
		if len(p) > maxGameLocalPathLen {
			a.add("localpath-long", launchSeverityCritical, label, "本地路径过长")
		}
		if containsControlByte(p) {
			a.add("localpath-control", launchSeverityCritical, label, "本地路径含控制字符")
		}
		if isUNC(p) {
			a.add("localpath-unc", launchSeverityCritical, label, "不允许把网络共享作为本地路径")
		}
		if !filepath.IsAbs(p) {
			a.add("localpath-not-absolute", launchSeverityCritical, label, "本地路径必须是绝对路径")
		}
		if hasTraversalSegment(p) {
			a.add("localpath-traversal", launchSeverityCritical, label, "本地路径含目录穿越段")
		}
		if !containedInAnyRoot(p, roots) {
			a.add("localpath-outside", launchSeverityCritical, label, "本地路径逃逸出游戏目录")
		}
	}
	check("nativesDir", nativesDir)
	check("librariesDir", librariesDir)
	if strings.TrimSpace(assetsDir) != "" {
		check("assetsDir", assetsDir)
	}
	a.tally()
	return a
}
