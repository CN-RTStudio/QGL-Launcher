package main

// modauditgate_app.go —— mods 完整性审计启动闸门的 Wails 绑定。
// 决策纯逻辑在 modauditgate.go；本文件负责解析受信根、读基线、建当前快照、
// 记录审计事件，再转调决策内核，并把“拦截”翻译成 LaunchGame 可返回的错误。

import (
	"fmt"
	"os"
	"strings"
)

// ModsAuditBaselineStatus 汇总“基线是否存在”等闸门预检所需的静态信息。
type ModsAuditBaselineStatus struct {
	HasBaseline   bool   `json:"hasBaseline"`
	BaselineAt    string `json:"baselineAt,omitempty"`
	BaselineDirs  int    `json:"baselineDirs"`
	BaselineFiles int    `json:"baselineFiles"`
}

// GetModsAuditBaselineStatus 返回基线账本的静态信息，供前端预检页展示
// “已建立基线 / 尚未建立基线”。读取失败视为无基线（不把错误抛给用户）。
func (a *App) GetModsAuditBaselineStatus() ModsAuditBaselineStatus {
	status := ModsAuditBaselineStatus{HasBaseline: false}
	baseline, err := loadModAuditSnapshot(a.modAuditBaselinePath())
	if err != nil || baseline == nil {
		return status
	}
	status.HasBaseline = true
	status.BaselineAt = baseline.CreatedAt
	status.BaselineDirs = len(baseline.Dirs)
	files := 0
	for _, d := range baseline.Dirs {
		files += len(d.Entries)
	}
	status.BaselineFiles = files
	return status
}

// EnsureModsAuditReportsDir 确保报告导出目录存在（供前端点击“导出”前预检）。
func (a *App) EnsureModsAuditReportsDir() error {
	dir := a.modAuditReportPath()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return modAuditError("报告目录创建失败")
	}
	return nil
}

// SetModsAuditForceLaunch 设置启动闸门的强制放行开关。默认关闭：发现被篡改的
// mod 时启动会被拦截；用户明确确认风险后可打开，本会话内有效（不落盘持久化，
// 避免“上次强放行的坏习惯”被静默延续到下一次启动）。
func (a *App) SetModsAuditForceLaunch(force bool) {
	a.modsAuditForceLaunch = force
}

// GetModsAuditForceLaunch 返回当前强制放行开关状态，供前端预检页展示。
func (a *App) GetModsAuditForceLaunch() bool {
	return a.modsAuditForceLaunch
}

// PreflightModsAudit 供前端在“启动前 / 一键体检”主动调用：跑一次完整对账并给出
// 闸门决策，不修改任何文件。与 LaunchGame 内部的强制闸门共享同一套内核口径，
// 前端可据此提示用户“存在被篡改 mod，是否强制放行”。
func (a *App) PreflightModsAudit(versionID string) (*ModAuditGateDecision, error) {
	if versionID != "" && (strings.Contains(versionID, "..") ||
		strings.Contains(versionID, "/") || strings.Contains(versionID, "\\")) {
		return nil, modAuditError("版本ID包含非法字符")
	}
	baseline, err := loadModAuditSnapshot(a.modAuditBaselinePath())
	if err != nil {
		return nil, modAuditError("mods 审计基线读取失败")
	}
	roots := a.auditModsRoots(versionID)
	current, _, _, err := buildModAuditSnapshot(roots, defaultModAuditLimits())
	if err != nil {
		return nil, modAuditError("mods 目录扫描失败")
	}
	report := auditModsAgainstBaseline(current, baseline)
	decision := decideModAuditGate(report, baseline != nil, a.modsAuditForceLaunch)
	return &decision, nil
}

// enforceModsAuditBeforeLaunch 是 LaunchGame 内的强制闸门：存在被篡改 mod 且未
// 开启强制放行时直接返回错误、阻止拉起 JVM。无论放行与否都写审计事件。
func (a *App) enforceModsAuditBeforeLaunch(versionID string) error {
	baseline, err := loadModAuditSnapshot(a.modAuditBaselinePath())
	if err != nil {
		return fmt.Errorf("mods 完整性审计: 基线读取失败: %v", err)
	}
	roots := a.auditModsRoots(versionID)
	current, skipped, limitHit, err := buildModAuditSnapshot(roots, defaultModAuditLimits())
	if err != nil {
		return fmt.Errorf("mods 完整性审计: 目录扫描失败: %v", err)
	}
	report := auditModsAgainstBaseline(current, baseline)
	report.Skipped = skipped
	report.LimitHit = limitHit

	decision := decideModAuditGate(report, baseline != nil, a.modsAuditForceLaunch)
	if decision.Kind == ModAuditGateBlock {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			"mods-audit-gate", modAuditGateEventText(decision))
		return fmt.Errorf("mods 完整性审计: %s（首个: %s）", decision.Reason, decision.FirstTainted)
	}
	if decision.Kind == ModAuditGateAllowWarn && decision.ForceUsed {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			"mods-audit-gate", modAuditGateEventText(decision))
		return nil
	}
	severity := auditSeverityInfo
	if decision.Kind == ModAuditGateAllowWarn {
		severity = auditSeverityWarn
	}
	recordSecurityEvent(auditCategoryJarScan, severity, auditActionDetected,
		"mods-audit-gate", modAuditGateEventText(decision))
	return nil
}
