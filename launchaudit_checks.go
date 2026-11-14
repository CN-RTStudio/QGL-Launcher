package main

import (
	"path/filepath"
	"runtime"
	"strings"
)

func auditJavaExe(exe string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(exe) == "" {
		return append(out, LaunchFinding{"java-empty", launchSeverityCritical, "javaExe", "java 可执行路径为空"})
	}
	if len(exe) > maxPathLen {
		out = append(out, LaunchFinding{"java-long", launchSeverityCritical, "javaExe", "java 可执行路径过长"})
	}
	if containsControlByte(exe) {
		out = append(out, LaunchFinding{"java-control", launchSeverityCritical, "javaExe", "java 可执行路径含控制字符"})
	}
	if isUNC(exe) {
		out = append(out, LaunchFinding{"java-unc", launchSeverityCritical, "javaExe", "不允许使用网络共享上的 java"})
	}
	if !filepath.IsAbs(exe) {
		out = append(out, LaunchFinding{"java-not-absolute", launchSeverityCritical, "javaExe", "java 可执行必须是绝对路径"})
	}
	if hasTraversalSegment(exe) {
		out = append(out, LaunchFinding{"java-traversal", launchSeverityCritical, "javaExe", "java 可执行路径含目录穿越段"})
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(exe), ".exe") {
		out = append(out, LaunchFinding{"java-not-exe", launchSeverityCritical, "javaExe", "Windows 上 java 启动器必须是 .exe"})
	}
	return out
}

func auditWorkDir(dir string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(dir) == "" {
		return append(out, LaunchFinding{"workdir-empty", launchSeverityCritical, "workDir", "工作目录为空"})
	}
	if len(dir) > maxPathLen {
		out = append(out, LaunchFinding{"workdir-long", launchSeverityCritical, "workDir", "工作目录路径过长"})
	}
	if containsControlByte(dir) {
		out = append(out, LaunchFinding{"workdir-control", launchSeverityCritical, "workDir", "工作目录含控制字符"})
	}
	if isUNC(dir) {
		out = append(out, LaunchFinding{"workdir-unc", launchSeverityCritical, "workDir", "不允许把网络共享作为工作目录"})
	}
	if !filepath.IsAbs(dir) {
		out = append(out, LaunchFinding{"workdir-not-absolute", launchSeverityCritical, "workDir", "工作目录必须是绝对路径"})
	}
	if hasTraversalSegment(dir) {
		out = append(out, LaunchFinding{"workdir-traversal", launchSeverityCritical, "workDir", "工作目录含目录穿越段"})
	}
	if !containedInAnyRoot(dir, roots) {
		out = append(out, LaunchFinding{"workdir-outside", launchSeverityCritical, "workDir", "工作目录不在允许的安装根内"})
	}
	return out
}
