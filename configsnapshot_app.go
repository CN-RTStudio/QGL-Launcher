package main

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
