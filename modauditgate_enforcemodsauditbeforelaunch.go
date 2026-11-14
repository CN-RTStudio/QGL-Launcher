package main

import (
	"fmt"
	"strings"
)

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

func modAuditGateWarnReason(added, missing int) string {
	parts := []string{}
	if added > 0 {
		parts = append(parts, fmt.Sprintf("新增 %d", added))
	}
	if missing > 0 {
		parts = append(parts, fmt.Sprintf("缺失 %d", missing))
	}
	return "mods 目录与基线有差异（" + strings.Join(parts, "、") + "），已放行，请留意来源"
}

// modAuditGateEventText 生成写审计事件的中文摘要。
func modAuditGateEventText(d ModAuditGateDecision) string {
	base := "mods 完整性启动闸门"
	if !d.HasBaseline {
		return base + ": 无基线，放行"
	}
	switch d.Kind {
	case ModAuditGateBlock:
		return fmt.Sprintf("%s: 拦截（篡改 %d，首个: %s）", base, d.Tampered, d.FirstTainted)
	case ModAuditGateAllowWarn:
		if d.ForceUsed {
			return fmt.Sprintf("%s: 强制放行（篡改 %d，首个: %s）", base, d.Tampered, d.FirstTainted)
		}
		return fmt.Sprintf("%s: 放行但提示（新增 %d / 缺失 %d）", base, d.Added, d.Missing)
	default:
		return fmt.Sprintf("%s: 放行（一致 %d）", base, d.Consistent)
	}
}
