package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
func (a *App) ensureConfigSnapshotLoaded() {
	defaultConfigSnapshot.Lock()
	defer defaultConfigSnapshot.Unlock()
	if !defaultConfigSnapshot.loaded {
		defaultConfigSnapshot.baseline = loadConfigSnapshotFile(a.configSnapshotPath())
		defaultConfigSnapshot.loaded = true
	}
}

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

func normSnapshotPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimRight(p, "/\\")
	return strings.ToLower(p)
}

// configSnapshotEqual 判断两份快照完全一致（落盘前判断是否真的变了）。
func configSnapshotEqual(a, b configSnapshot) bool {
	return normSnapshotPath(a.JavaPath) == normSnapshotPath(b.JavaPath) &&
		a.MaxMemMB == b.MaxMemMB &&
		normSnapshotPath(a.GameDir) == normSnapshotPath(b.GameDir) &&
		a.VersionID == b.VersionID &&
		a.AuthTypeLabel == b.AuthTypeLabel
}

// configSnapshotDiffsText 把变化字段整理成一行审计文本。
func configSnapshotDiffsText(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return "关键配置被外部篡改: " + strings.Join(fields, "、")
}

// configSnapshotSanitize 对快照字段做收口（控制字符剥离 + 限长），防把畸形
// 值写进基线文件本身。
func configSnapshotSanitize(s configSnapshot) configSnapshot {
	return configSnapshot{
		JavaPath:      sanitizeLedgerField(s.JavaPath, 1024),
		MaxMemMB:      s.MaxMemMB,
		GameDir:       sanitizeLedgerField(s.GameDir, 1024),
		VersionID:     sanitizeLedgerField(s.VersionID, 128),
		AuthTypeLabel: sanitizeLedgerField(s.AuthTypeLabel, 32),
	}
}
