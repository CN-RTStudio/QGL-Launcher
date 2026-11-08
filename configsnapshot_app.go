package main

// configsnapshot_app.go —— 关键配置防篡改基线的 App 绑定层。
//
// 生命周期：
//   1. 本进程每次可信写入全局/用户配置（SaveGlobalConfig / SaveUserConfig）
//      成功后调用 UpdateConfigGuardBaseline 刷新基线（用户 UI 主动改不误报）；
//   2. LaunchGame 启动预检时调用 CheckConfigGuardBaseline：基线存在且关键字段
//      在两次本进程会话之间被改动 → critical 审计并阻断启动；
//   3. 首次启动没有基线 → 直接建立基线放行。
// 持久化文件 configguard-snapshot.json 复用有界私有写，损坏按“无基线”处理。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// configGuardMaxBytes 基线文件体积上限。
const configGuardMaxBytes = 4096

// configSnapshotStore 是配置基线的内存权威。
type configSnapshotStore struct {
	sync.Mutex
	loaded   bool
	baseline configSnapshot
}

// defaultConfigSnapshot 是全局配置基线单例。
var defaultConfigSnapshot configSnapshotStore

// configSnapshotPath 返回基线文件路径（QGL 目录下）。
func (a *App) configSnapshotPath() string {
	return filepath.Join(a.GetQGLDir(), "configguard-snapshot.json")
}

// loadConfigSnapshotFile 从磁盘有界加载基线；文件缺失按无基线处理，
// 损坏 / 超限按无基线处理并记审计。
func loadConfigSnapshotFile(path string) configSnapshot {
	var s configSnapshot
	if err := readLocalJSONBounded(path, &s, configGuardMaxBytes, "configguard-snapshot"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionStripped,
				"configguard", fmt.Sprintf("配置基线读取失败，按无基线处理: %v", err))
		}
		return configSnapshot{}
	}
	return configSnapshotSanitize(s)
}

// saveConfigSnapshotLocked 原子私有写基线；失败只记审计事件，不上抛。
func (a *App) saveConfigSnapshotLocked() {
	if err := writePrivateJSONBounded(a.configSnapshotPath(), defaultConfigSnapshot.baseline, configGuardMaxBytes); err != nil {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionFailed,
			"configguard", fmt.Sprintf("配置基线写盘失败: %v", err))
	}
}

// ensureConfigSnapshotLoaded 确保内存基线已从磁盘加载。
func (a *App) ensureConfigSnapshotLoaded() {
	defaultConfigSnapshot.Lock()
	defer defaultConfigSnapshot.Unlock()
	if !defaultConfigSnapshot.loaded {
		defaultConfigSnapshot.baseline = loadConfigSnapshotFile(a.configSnapshotPath())
		defaultConfigSnapshot.loaded = true
	}
}

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
