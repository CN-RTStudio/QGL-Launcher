package main

import (
	"os"
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
