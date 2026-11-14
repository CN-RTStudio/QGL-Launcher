package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func auditClasspath(workDir string, entries []string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if len(entries) > maxClasspathEntries {
		return append(out, LaunchFinding{"cp-too-many", launchSeverityCritical, "classpath", "classpath 条目过多"})
	}
	for i, entry := range entries {
		field := fmt.Sprintf("classpath[%d]", i)
		if entry == "" {
			out = append(out, LaunchFinding{"cp-empty", launchSeverityCritical, field, "classpath 含空条目（等同当前目录）"})
			continue
		}
		if len(entry) > maxPathLen {
			out = append(out, LaunchFinding{"cp-long", launchSeverityCritical, field, "classpath 条目过长"})
			continue
		}
		if containsControlByte(entry) {
			out = append(out, LaunchFinding{"cp-control", launchSeverityCritical, field, "classpath 条目含控制字符"})
			continue
		}
		if filepath.IsAbs(entry) || isUNC(entry) {
			out = append(out, LaunchFinding{"cp-absolute", launchSeverityCritical, field, "classpath 条目必须相对工作目录"})
			continue
		}
		if hasTraversalSegment(entry) {
			out = append(out, LaunchFinding{"cp-traversal", launchSeverityCritical, field, "classpath 条目含目录穿越段"})
			continue
		}
		joined := filepath.Join(workDir, entry)
		if _, inWork := PathWithin(workDir, joined); !inWork || !containedInAnyRoot(joined, roots) {
			out = append(out, LaunchFinding{"cp-outside", launchSeverityCritical, field, "classpath 条目逃逸出允许目录"})
		}
	}
	return out
}

func auditAbsJar(target string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(target) == "" {
		return out // 主类模式时空，合法
	}
	if len(target) > maxPathLen {
		return append(out, LaunchFinding{"absjar-long", launchSeverityCritical, "jar", "jar 路径过长"})
	}
	if containsControlByte(target) {
		return append(out, LaunchFinding{"absjar-control", launchSeverityCritical, "jar", "jar 路径含控制字符"})
	}
	if isUNC(target) {
		return append(out, LaunchFinding{"absjar-unc", launchSeverityCritical, "jar", "不允许运行网络共享上的 jar"})
	}
	if !filepath.IsAbs(target) {
		return append(out, LaunchFinding{"absjar-not-absolute", launchSeverityCritical, "jar", "安装器 jar 必须是绝对路径"})
	}
	if hasTraversalSegment(target) {
		return append(out, LaunchFinding{"absjar-traversal", launchSeverityCritical, "jar", "jar 路径含目录穿越段"})
	}
	if !strings.EqualFold(filepath.Ext(target), ".jar") {
		return append(out, LaunchFinding{"absjar-not-jar", launchSeverityCritical, "jar", "运行目标必须以 .jar 结尾"})
	}
	if !containedInAnyRoot(target, roots) {
		return append(out, LaunchFinding{"absjar-outside", launchSeverityCritical, "jar", "jar 不在允许的目录集合内"})
	}
	return out
}
