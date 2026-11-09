package main

import (
	"fmt"
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

// auditWorkDir 校验工作目录：绝对、有界、非 UNC、无穿越、且落在允许根集合内。
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

// auditJarRelPath 校验 -jar 目标。它必须是相对 WorkDir 的单个 .jar 文件名（或含
// 子目录但不得逃逸），禁止绝对路径与 ".." 段；解析后必须仍在 WorkDir 与允许根内。
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

// auditClasspath 校验 -classpath 各条目：数量有界、非空（空条目=当前目录）、相对
// WorkDir、无穿越，解析后仍在允许根内。
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

// auditMainClass 校验主类标识：允许 a.b.C 形式，或 module/a.b.C 形式；拒前导 '-'
// （伪装 JVM 选项）、空白、控制符与非法字符。
