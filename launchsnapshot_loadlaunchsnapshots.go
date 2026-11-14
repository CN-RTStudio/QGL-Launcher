package main

import (
	"errors"
	"fmt"
	"os"
)

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
