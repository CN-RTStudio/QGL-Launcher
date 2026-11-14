package main

import ()

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
