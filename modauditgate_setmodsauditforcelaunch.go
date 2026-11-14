package main

import (
	"strings"
)

func (a *App) SetModsAuditForceLaunch(force bool) {
	a.modsAuditForceLaunch = force
}

// GetModsAuditForceLaunch 返回当前强制放行开关状态，供前端预检页展示。
func (a *App) GetModsAuditForceLaunch() bool {
	return a.modsAuditForceLaunch
}

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
