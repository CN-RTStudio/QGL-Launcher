package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxLaunchSnapshots = 10

// maxSnapshotFieldLen 单个字段长度上限（Java 路径 / 版本 ID 都可能很长）。
const maxSnapshotFieldLen = 1024

// LaunchSnapshot 是一次启动的参数快照（可落盘，字段已收口）。
type LaunchSnapshot struct {
	VersionID        string `json:"versionId"`
	JavaPath         string `json:"javaPath"`
	JavaVersion      string `json:"javaVersion,omitempty"`
	MaxMemMB         int    `json:"maxMemMB,omitempty"`
	AuthType         string `json:"authType,omitempty"`
	ModsCount        int    `json:"modsCount,omitempty"`
	OnlineMode       bool   `json:"onlineMode"`
	PreflightBlocked bool   `json:"preflightBlocked,omitempty"`
	PreflightIssues  int    `json:"preflightIssues,omitempty"`
	CreatedAt        string `json:"createdAt"` // RFC3339
}

// sanitizeSnapshotField 单字段收口：去控制字符并截断，空串归一为 ""。
func sanitizeSnapshotField(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

const launchSnapshotFileName = "launch-snapshot.json"
const launchSnapshotMaxReadBytes int64 = 256 * 1024

var defaultLaunchSnapshotStore launchSnapshotStore

type launchSnapshotStore struct {
	sync.Mutex
	loaded bool
	items  []LaunchSnapshot
}

func (a *App) launchSnapshotDir() string {
	return a.GetQGLDir()
}
func launchSnapshotFilePath(qglDir string) string {
	return filepath.Join(qglDir, launchSnapshotFileName)
}

func loadLaunchSnapshots(path string) []LaunchSnapshot {
	var items []LaunchSnapshot
	if err := readLocalJSONBounded(path, &items, launchSnapshotMaxReadBytes, "launch-snapshot"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			recordSecurityEvent("launch-snapshot", auditSeverityWarn, auditActionStripped,
				"launch-snapshot", fmt.Sprintf("启动快照读取失败，按空处理: %v", err))
		}
		return nil
	}
	clean := make([]LaunchSnapshot, 0, len(items))
	for _, s := range items {
		if s.VersionID == "" || s.CreatedAt == "" {
			continue // 结构不合法条目整体丢弃
		}
		clean = append(clean, s)
	}
	sortSnapshotsNewestFirst(clean)
	if len(clean) > maxLaunchSnapshots {
		clean = clean[:maxLaunchSnapshots]
	}
	return clean
}

func saveLaunchSnapshots(path string, items []LaunchSnapshot) {
	if err := writePrivateJSONBounded(path, items, launchSnapshotMaxReadBytes); err != nil {
		recordSecurityEvent("launch-snapshot", auditSeverityWarn, auditActionStripped,
			"launch-snapshot", fmt.Sprintf("启动快照写盘失败: %v", err))
	}
}
func (a *App) ensureLaunchSnapshotsLoaded() {
	store := &defaultLaunchSnapshotStore
	store.Lock()
	defer store.Unlock()
	if store.loaded {
		return
	}
	store.items = loadLaunchSnapshots(launchSnapshotFilePath(a.launchSnapshotDir()))
	store.loaded = true
}
func (a *App) recordLaunchSnapshot(snap LaunchSnapshot) {
	a.ensureLaunchSnapshotsLoaded()
	store := &defaultLaunchSnapshotStore
	store.Lock()
	store.items = decideSnapshotRetention(store.items, snap, maxLaunchSnapshots)
	sortSnapshotsNewestFirst(store.items)
	saveLaunchSnapshots(launchSnapshotFilePath(a.launchSnapshotDir()), store.items)
	store.Unlock()
}

func (a *App) ListLaunchSnapshots() []LaunchSnapshot {
	a.ensureLaunchSnapshotsLoaded()
	store := &defaultLaunchSnapshotStore
	store.Lock()
	defer store.Unlock()
	out := make([]LaunchSnapshot, len(store.items))
	copy(out, store.items)
	return out
}

// ClearLaunchSnapshots 清空启动快照（仅本机文件与内存）。
func (a *App) ClearLaunchSnapshots() error {
	store := &defaultLaunchSnapshotStore
	store.Lock()
	store.items = nil
	store.loaded = true
	store.Unlock()
	path := launchSnapshotFilePath(a.launchSnapshotDir())
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	recordSecurityEvent("launch-snapshot", auditSeverityInfo, auditActionDetected,
		"launch-snapshot", "启动快照已清空")
	return nil
}

func buildLaunchSnapshot(versionID, javaPath, javaVersion, authType string,
	maxMemMB, modsCount int, onlineMode bool, preflightBlocked bool, preflightIssues int) LaunchSnapshot {
	return LaunchSnapshot{
		VersionID:        sanitizeSnapshotField(versionID, maxSnapshotFieldLen),
		JavaPath:         sanitizeSnapshotField(javaPath, maxSnapshotFieldLen),
		JavaVersion:      sanitizeSnapshotField(javaVersion, 128),
		MaxMemMB:         maxMemMB,
		AuthType:         sanitizeSnapshotField(authType, 64),
		ModsCount:        modsCount,
		OnlineMode:       onlineMode,
		PreflightBlocked: preflightBlocked,
		PreflightIssues:  preflightIssues,
		CreatedAt:        time.Now().Format(time.RFC3339),
	}
}

// decideSnapshotRetention 纯函数：新增一条快照并淘汰最旧，返回应写盘的列表。
// 入参不被修改（“纯函数不改入参”与现有模块口径一致）。上限 <= 0 时用默认值。
func decideSnapshotRetention(snapshots []LaunchSnapshot, next LaunchSnapshot, capN int) []LaunchSnapshot {
	if capN <= 0 {
		capN = maxLaunchSnapshots
	}
	out := append([]LaunchSnapshot(nil), snapshots...)
	out = append(out, next)
	if len(out) > capN {
		out = out[len(out)-capN:]
	}
	return out
}

// sortSnapshotsNewestFirst 按 CreatedAt 倒序排序（RFC3339 字典序即时间序）。
func sortSnapshotsNewestFirst(snaps []LaunchSnapshot) {
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].CreatedAt > snaps[j].CreatedAt
	})
}
