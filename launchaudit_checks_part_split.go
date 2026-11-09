package main

import (
	"path/filepath"
	"strings"
)

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
