package main

import (
	"fmt"
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

func auditAbsClasspath(entries []string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if len(entries) > maxClasspathEntries {
		return append(out, LaunchFinding{"abscp-too-many", launchSeverityCritical, "classpath", "classpath 条目过多"})
	}
	for i, entry := range entries {
		field := fmt.Sprintf("classpath[%d]", i)
		if entry == "" {
			out = append(out, LaunchFinding{"abscp-empty", launchSeverityCritical, field, "classpath 含空条目（等同当前目录）"})
			continue
		}
		if len(entry) > maxPathLen {
			out = append(out, LaunchFinding{"abscp-long", launchSeverityCritical, field, "classpath 条目过长"})
			continue
		}
		if containsControlByte(entry) {
			out = append(out, LaunchFinding{"abscp-control", launchSeverityCritical, field, "classpath 条目含控制字符"})
			continue
		}
		if isUNC(entry) {
			out = append(out, LaunchFinding{"abscp-unc", launchSeverityCritical, field, "不允许把网络共享加入 classpath"})
			continue
		}
		if !filepath.IsAbs(entry) {
			out = append(out, LaunchFinding{"abscp-not-absolute", launchSeverityCritical, field, "安装器 classpath 必须是绝对路径"})
			continue
		}
		if hasTraversalSegment(entry) {
			out = append(out, LaunchFinding{"abscp-traversal", launchSeverityCritical, field, "classpath 条目含目录穿越段"})
			continue
		}
		if !strings.EqualFold(filepath.Ext(entry), ".jar") {
			out = append(out, LaunchFinding{"abscp-not-jar", launchSeverityCritical, field, "classpath 条目必须以 .jar 结尾"})
			continue
		}
		if !containedInAnyRoot(entry, roots) {
			out = append(out, LaunchFinding{"abscp-outside", launchSeverityCritical, field, "classpath 条目逃逸出允许目录"})
		}
	}
	return out
}

// ExternalJVMPlan 描述“运行外部安装器 JVM”需要审计的各段。与 LaunchPlan 的区别：
// Jar/Classpath 允许绝对路径，但必须落在显式给出的 AllowedRoots 内。
type ExternalJVMPlan struct {
	JavaExe      string
	WorkDir      string
	JarAbsPath   string   // -jar 绝对目标（与 MainClass 二选一）
	Classpath    []string // 绝对路径 .jar 集合
	MainClass    string
	ProgramArgs  []string
	AllowedRoots []string
}

// AuditExternalJVM 审计安装器 / 第三方 jar 的 JVM 启动：java 可执行、工作目录、
// 绝对 jar / classpath 的目录归属、主类与程序参数。任一 critical 都应阻止启动。
func AuditExternalJVM(plan ExternalJVMPlan) *LaunchAudit {
	a := &LaunchAudit{}
	a.Findings = append(a.Findings, auditJavaExe(plan.JavaExe)...)
	a.Findings = append(a.Findings, auditWorkDir(plan.WorkDir, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditAbsJar(plan.JarAbsPath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditAbsClasspath(plan.Classpath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditMainClass(plan.MainClass)...)
	a.Findings = append(a.Findings, auditProgramArgs(plan.ProgramArgs)...)
	if strings.TrimSpace(plan.JarAbsPath) == "" && strings.TrimSpace(plan.MainClass) == "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-missing", launchSeverityCritical, "entry", "必须指定 -jar 目标或主类之一"})
	}
	if strings.TrimSpace(plan.JarAbsPath) != "" && strings.TrimSpace(plan.MainClass) != "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-ambiguous", launchSeverityWarn, "entry", "同时给出了 -jar 与主类"})
	}
	a.tally()
	return a
}
