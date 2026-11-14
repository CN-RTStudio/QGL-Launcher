package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type configSnapshot struct {
	JavaPath      string `json:"javaPath"`
	MaxMemMB      int64  `json:"maxMemMB"`
	GameDir       string `json:"gameDir"`
	VersionID     string `json:"versionID"`
	AuthTypeLabel string `json:"authTypeLabel"`
}

// configSnapshotDiff 是快照与基线比对的结果。
type configSnapshotDiff struct {
	Changed bool
	Fields  []string // 变化字段的人类可读描述
}

// configSnapshotChanged 比较当前快照与基线（归一化差异被忽略，如路径大小写
// 与尾分隔符）。基线字段为空串 / 0 时跳过该项（未建立过基线视为首次）。
func configSnapshotChanged(base, cur configSnapshot) configSnapshotDiff {
	var d configSnapshotDiff
	if base.JavaPath != "" && normSnapshotPath(base.JavaPath) != normSnapshotPath(cur.JavaPath) {
		d.Changed = true
		d.Fields = append(d.Fields, "Java 路径")
	}
	if base.MaxMemMB != 0 && base.MaxMemMB != cur.MaxMemMB {
		d.Changed = true
		d.Fields = append(d.Fields, "内存上限")
	}
	if base.GameDir != "" && normSnapshotPath(base.GameDir) != normSnapshotPath(cur.GameDir) {
		d.Changed = true
		d.Fields = append(d.Fields, "游戏目录")
	}
	if base.VersionID != "" && base.VersionID != cur.VersionID {
		d.Changed = true
		d.Fields = append(d.Fields, "版本选择")
	}
	if base.AuthTypeLabel != "" && base.AuthTypeLabel != cur.AuthTypeLabel {
		d.Changed = true
		d.Fields = append(d.Fields, "登录类型")
	}
	return d
}

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
