package main

import (
	"path/filepath"
	"strings"
)

func auditJarRelPath(workDir, jar string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(jar) == "" {
		return out // 未使用 -jar（主类模式）时为空，合法。
	}
	if len(jar) > maxPathLen {
		return append(out, LaunchFinding{"jar-long", launchSeverityCritical, "jar", "jar 路径过长"})
	}
	if containsControlByte(jar) {
		return append(out, LaunchFinding{"jar-control", launchSeverityCritical, "jar", "jar 路径含控制字符"})
	}
	if filepath.IsAbs(jar) || isUNC(jar) {
		return append(out, LaunchFinding{"jar-absolute", launchSeverityCritical, "jar", "jar 目标必须是相对工作目录的路径"})
	}
	if hasTraversalSegment(jar) {
		return append(out, LaunchFinding{"jar-traversal", launchSeverityCritical, "jar", "jar 目标含目录穿越段"})
	}
	if !strings.EqualFold(filepath.Ext(jar), ".jar") {
		return append(out, LaunchFinding{"jar-not-jar", launchSeverityCritical, "jar", "-jar 目标必须以 .jar 结尾"})
	}
	joined := filepath.Join(workDir, jar)
	if _, ok := PathWithin(workDir, joined); !ok {
		out = append(out, LaunchFinding{"jar-escapes-workdir", launchSeverityCritical, "jar", "jar 解析后逃逸出工作目录"})
	}
	if !containedInAnyRoot(joined, roots) {
		out = append(out, LaunchFinding{"jar-outside-root", launchSeverityCritical, "jar", "jar 解析后不在允许的安装根内"})
	}
	return out
}
