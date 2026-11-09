package main

import "strings"

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
