package main

import (
	"fmt"
)

// UpdateConfigGuardBaseline 用最新可信配置刷新基线（本进程自己写配置后调用，
// 防止把“用户 UI 主动修改”误判为外部篡改）。
func (a *App) UpdateConfigGuardBaseline(s configSnapshot) {
	a.ensureConfigSnapshotLoaded()
	s = configSnapshotSanitize(s)
	defaultConfigSnapshot.Lock()
	defer defaultConfigSnapshot.Unlock()
	if configSnapshotEqual(defaultConfigSnapshot.baseline, s) {
		return
	}
	defaultConfigSnapshot.baseline = s
	a.saveConfigSnapshotLocked()
}

// CheckConfigGuardBaseline 启动预检：比对当前关键配置与基线。
// 返回 err 表示关键配置疑似被外部篡改，调用方应拒绝启动；
// 无基线（首次启动）时建立基线并放行。
func (a *App) CheckConfigGuardBaseline(cur configSnapshot) error {
	a.ensureConfigSnapshotLoaded()
	defaultConfigSnapshot.Lock()
	base := defaultConfigSnapshot.baseline
	hasBaseline := base.JavaPath != "" || base.GameDir != "" || base.VersionID != ""
	defaultConfigSnapshot.Unlock()

	cur = configSnapshotSanitize(cur)
	if !hasBaseline {
		// 首次启动：没有可比对象，建立基线并放行。
		defaultConfigSnapshot.Lock()
		defaultConfigSnapshot.baseline = cur
		a.saveConfigSnapshotLocked()
		defaultConfigSnapshot.Unlock()
		return nil
	}

	diff := configSnapshotChanged(base, cur)
	if !diff.Changed {
		return nil
	}
	recordSecurityEvent(auditCategoryConfig, auditSeverityCritical, auditActionBlocked,
		"configguard", configSnapshotDiffsText(diff.Fields)+"；拒绝启动")
	return fmt.Errorf("关键配置疑似被外部篡改: %s", configSnapshotDiffsText(diff.Fields))
}

// configSnapshotOf 从全局/用户配置构建当前快照（App 层字段来源统一收口）。
func (a *App) configSnapshotOf(g *GlobalConfig, u *UserConfig) configSnapshot {
	s := configSnapshot{}
	if g != nil {
		s.JavaPath = g.JavaPath
		s.MaxMemMB = int64(g.MaxMemory)
		s.GameDir = g.MinecraftDir
	}
	if u != nil {
		s.VersionID = u.SelectedVersion
	}
	return configSnapshotSanitize(s)
}
