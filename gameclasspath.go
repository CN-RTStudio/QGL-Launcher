package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// 上限取“远大于任何真实整合包、又能拦住畸形灌入”的值：现代大型整合包 classpath
	// 一般数百条，给到数千仍安全；不设会误伤正常模组的小上限。
	maxGameClasspathEntries = 16384
	// natives/library 路径总长上限，与系统 MAX_PATH 级别对齐。
	maxGameLocalPathLen = 4096
)

type GameClasspathAudit struct {
	Findings    []LaunchFinding `json:"findings"`
	Critical    int             `json:"critical"`
	Warns       int             `json:"warns"`
	SafeEntries []string        `json:"safeEntries"` // 通过全部强制检查的条目（保持原顺序、去重）
	Rejected    int             `json:"rejected"`
}

func (g *GameClasspathAudit) add(code, severity, field, detail string) {
	g.Findings = append(g.Findings, LaunchFinding{Code: code, Severity: severity, Field: field, Detail: detail})
	switch severity {
	case launchSeverityCritical:
		g.Critical++
	case launchSeverityWarn:
		g.Warns++
	}
}
func (g *GameClasspathAudit) HasCritical() bool { return g.Critical > 0 }

func (g *GameClasspathAudit) FirstCriticalCode() string {
	for _, f := range g.Findings {
		if f.Severity == launchSeverityCritical {
			return f.Code
		}
	}
	return ""
}

// classifyGameClasspathEntry 判定单条 classpath 条目的安全性。返回 "" 表示安全，否则
// 返回稳定错误 code。roots 为允许的根集合（通常是 .minecraft）。
func classifyGameClasspathEntry(entry string, roots []string) string {
	if entry == "" {
		return "gcp-empty"
	}
	if len(entry) > maxPathLen {
		return "gcp-long"
	}
	if containsControlByte(entry) {
		return "gcp-control"
	}
	if isUNC(entry) {
		return "gcp-unc"
	}
	if !filepath.IsAbs(entry) {
		return "gcp-not-absolute"
	}
	if hasTraversalSegment(entry) {
		return "gcp-traversal"
	}
	if !strings.EqualFold(filepath.Ext(entry), ".jar") {
		return "gcp-not-jar"
	}
	if !containedInAnyRoot(entry, roots) {
		return "gcp-outside-root"
	}
	return ""
}

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
