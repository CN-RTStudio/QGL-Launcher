package main

import (
	"fmt"
	"os"
	"strings"
)

type ModAuditGateKind string

const (
	ModAuditGateAllow     ModAuditGateKind = "allow"      // 放行（含无基线 / 仅有提示）
	ModAuditGateBlock     ModAuditGateKind = "block"      // 拦截（存在未放行的篡改）
	ModAuditGateAllowWarn ModAuditGateKind = "allow-warn" // 放行但提示（新增 / 缺失）
)

// ModAuditGateDecision 是一次启动预检的决策结果，供前端预检页与审计事件消费。
type ModAuditGateDecision struct {
	Kind         ModAuditGateKind `json:"kind"`
	Blocked      bool             `json:"blocked"`
	ForceUsed    bool             `json:"forceUsed"`
	Tampered     int              `json:"tampered"`
	Added        int              `json:"added"`
	Missing      int              `json:"missing"`
	Consistent   int              `json:"consistent"`
	HasBaseline  bool             `json:"hasBaseline"`
	FirstTainted string           `json:"firstTainted,omitempty"` // 首个被篡改文件名
	Reason       string           `json:"reason,omitempty"`
}

// decideModAuditGate 把一次对账报告翻译成启动闸门决策。report 可为零值（无基线
// 时 current 全量 added）；hasBaseline 区分“首次审计”与“有基线但对账全新增”。
func decideModAuditGate(report ModAuditReport, hasBaseline bool, force bool) ModAuditGateDecision {
	d := ModAuditGateDecision{
		HasBaseline: hasBaseline,
		Tampered:    len(report.Tampered),
		Added:       len(report.Added),
		Missing:     len(report.Missing),
		Consistent:  report.Consistent,
	}
	if !hasBaseline {
		d.Kind = ModAuditGateAllow
		d.Reason = "尚无 mods 完整性基线，跳过启动拦截（建议先建立基线）"
		return d
	}
	if len(report.Tampered) > 0 {
		d.FirstTainted = report.Tampered[0].Name
		d.ForceUsed = force
		if !force {
			d.Blocked = true
			d.Kind = ModAuditGateBlock
			d.Reason = fmt.Sprintf("检测到 %d 个被篡改的 mod，已拦截启动", len(report.Tampered))
			return d
		}
		d.Kind = ModAuditGateAllowWarn
		d.Reason = fmt.Sprintf("检测到 %d 个被篡改的 mod，用户已强制放行", len(report.Tampered))
		return d
	}
	if len(report.Added) > 0 || len(report.Missing) > 0 {
		d.Kind = ModAuditGateAllowWarn
		d.Reason = modAuditGateWarnReason(d.Added, d.Missing)
		return d
	}
	d.Kind = ModAuditGateAllow
	d.Reason = "mods 目录与基线一致，允许启动"
	return d
}

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
