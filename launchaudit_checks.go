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

func auditMainClass(mainClass string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(mainClass) == "" {
		return out // -jar 模式下为空，合法。
	}
	if len(mainClass) > maxMainClassLen {
		return append(out, LaunchFinding{"main-long", launchSeverityCritical, "mainClass", "主类名过长"})
	}
	if containsControlByte(mainClass) || strings.ContainsAny(mainClass, " \t") {
		return append(out, LaunchFinding{"main-control", launchSeverityCritical, "mainClass", "主类名含空白或控制字符"})
	}
	if strings.HasPrefix(mainClass, "-") || strings.HasPrefix(mainClass, "@") {
		return append(out, LaunchFinding{"main-option-like", launchSeverityCritical, "mainClass", "主类名形似 JVM 选项或 argfile"})
	}
	cls := mainClass
	if idx := strings.Index(mainClass, "/"); idx >= 0 {
		cls = mainClass[idx+1:] // 丢掉可选的 module/ 前缀，仅校验类名部分
	}
	if cls == "" {
		return append(out, LaunchFinding{"main-empty-class", launchSeverityCritical, "mainClass", "缺少类名部分"})
	}
	for _, seg := range strings.Split(cls, ".") {
		if seg == "" {
			return append(out, LaunchFinding{"main-empty-segment", launchSeverityCritical, "mainClass", "主类名含空段"})
		}
		if !isJavaIdentSegment(seg) {
			return append(out, LaunchFinding{"main-bad-char", launchSeverityCritical, "mainClass", "主类名含非法字符"})
		}
	}
	return out
}

func isJavaIdentSegment(seg string) bool {
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' {
			continue
		}
		return false
	}
	return true
}
func auditProgramArgs(args []string) []LaunchFinding {
	var out []LaunchFinding
	if len(args) > maxLaunchArgs {
		return append(out, LaunchFinding{"args-too-many", launchSeverityCritical, "programArgs", "程序参数数量过多"})
	}
	for i, arg := range args {
		field := fmt.Sprintf("programArgs[%d]", i)
		if len(arg) > maxLaunchArgBytes {
			out = append(out, LaunchFinding{"arg-long", launchSeverityCritical, field, "单个程序参数过长"})
			continue
		}
		if containsControlByte(arg) {
			out = append(out, LaunchFinding{"arg-control", launchSeverityCritical, field, "程序参数含控制字符"})
		}
	}
	return out
}

func auditMemory(minMB, maxMB int) []LaunchFinding {
	var out []LaunchFinding
	if minMB < minMemoryMBLowerBound {
		out = append(out, LaunchFinding{"mem-min-small", launchSeverityCritical, "minMemory", "最小堆内存小于可启动下限"})
	}
	if maxMB < minMemoryMBLowerBound {
		out = append(out, LaunchFinding{"mem-max-small", launchSeverityCritical, "maxMemory", "最大堆内存小于可启动下限"})
	}
	if minMB > 0 && maxMB > 0 && minMB > maxMB {
		out = append(out, LaunchFinding{"mem-order", launchSeverityCritical, "memory", "最小堆内存大于最大堆内存"})
	}
	if maxMB > maxMemoryMBUpperBound {
		out = append(out, LaunchFinding{"mem-max-huge", launchSeverityWarn, "maxMemory", "最大堆内存超过合理上限"})
	}
	return out
}

// AuditLaunchPlan 聚合审计一整份启动目标计划，返回所有结论。
func AuditLaunchPlan(plan LaunchPlan) *LaunchAudit {
	a := &LaunchAudit{}
	a.Findings = append(a.Findings, auditJavaExe(plan.JavaExe)...)
	a.Findings = append(a.Findings, auditWorkDir(plan.WorkDir, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditJarRelPath(plan.WorkDir, plan.JarRelPath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditClasspath(plan.WorkDir, plan.Classpath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditMainClass(plan.MainClass)...)
	a.Findings = append(a.Findings, auditProgramArgs(plan.ProgramArgs)...)
	a.Findings = append(a.Findings, auditMemory(plan.MinMemoryMB, plan.MaxMemoryMB)...)
	// -jar 与主类必须二选一：两者都空等于没有启动入口；两者都给会造成调用歧义。
	// 这里直接 append 而不调用 add：所有结论统一由下方循环计数，避免重复累加。
	if strings.TrimSpace(plan.JarRelPath) == "" && strings.TrimSpace(plan.MainClass) == "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-missing", launchSeverityCritical, "entry", "必须指定 -jar 目标或主类之一"})
	}
	if strings.TrimSpace(plan.JarRelPath) != "" && strings.TrimSpace(plan.MainClass) != "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-ambiguous", launchSeverityWarn, "entry", "同时给出了 -jar 与主类，以 -jar 为准"})
	}
	a.tally()
	return a
}

// AuditServerLaunch 是 StartServer 的便捷封装：服务器固定用
// "<version>-server.jar" 且 jar 位于 ServerDir。Java 可执行由
// SelectJavaForVersion 单独保证，此处不重复审计 java，只校验工作目录、由版本名
// 拼出的 jar 是否会逃逸、以及内存边界。
func AuditServerLaunch(serverDir, version string, minMB, maxMB int, roots []string) *LaunchAudit {
	jar := ""
	if v := strings.TrimSpace(version); v != "" {
		jar = v + "-server.jar"
	}
	a := &LaunchAudit{}
	a.Findings = append(a.Findings, auditWorkDir(serverDir, roots)...)
	a.Findings = append(a.Findings, auditJarRelPath(serverDir, jar, roots)...)
	a.Findings = append(a.Findings, auditMemory(minMB, maxMB)...)
	if strings.TrimSpace(jar) == "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-missing", launchSeverityCritical, "entry", "版本名为空，无法定位 -jar 目标"})
	}
	a.tally()
	return a
}

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
