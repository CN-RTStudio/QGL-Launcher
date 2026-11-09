package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

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

// isJavaIdentSegment 校验主类名中的一段是否为合法 Java 标识（允许内部类的 '$'）。
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

// auditProgramArgs 只做“有界 + 无控制字符”校验：主类之后的参数会原样传给游戏 /
// 服务器 main，JVM 不再解析，因此 --username/-x 等都是合法的，不能按 JVM 选项拦。
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

// auditMemory 校验堆内存边界：正整数、下限 sanity、min 不得大于 max、设一个极大的
// 上限仅用于拦截荒谬 / 溢出值，不做会误杀正常配置的小上限。
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

// auditAbsJar 校验一个“绝对路径”的 -jar 目标：必须绝对、.jar、无穿越/控制符，且落在
// 任一允许根内。安装器（Forge/OptiFine/下载的第三方安装器）的 jar 往往位于 mcDir 或
// 临时目录，不能套用 auditJarRelPath 的“必须相对工作目录”规则。
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

// auditAbsClasspath 校验绝对路径形式的 -classpath 各条目：数量有界、绝对、.jar、无
// 穿越/控制符、落在允许根集合内。
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
