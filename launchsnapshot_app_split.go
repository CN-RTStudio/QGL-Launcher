package main

import (
	"errors"
	"fmt"
	"os"
)

// saveLaunchSnapshots 原子私有写快照。失败只记审计事件，不向上抛（非关键路径）。
func saveLaunchSnapshots(path string, items []LaunchSnapshot) {
	if err := writePrivateJSONBounded(path, items, launchSnapshotMaxReadBytes); err != nil {
		recordSecurityEvent("launch-snapshot", auditSeverityWarn, auditActionStripped,
			"launch-snapshot", fmt.Sprintf("启动快照写盘失败: %v", err))
	}
}

// ensureLaunchSnapshotsLoaded 确保内存快照已从磁盘加载（每个 App 进程一次）。
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

// recordLaunchSnapshot 记录一次启动参数快照并持久化（LaunchGame 预检后调用）。
func (a *App) recordLaunchSnapshot(snap LaunchSnapshot) {
	a.ensureLaunchSnapshotsLoaded()
	store := &defaultLaunchSnapshotStore
	store.Lock()
	store.items = decideSnapshotRetention(store.items, snap, maxLaunchSnapshots)
	sortSnapshotsNewestFirst(store.items)
	saveLaunchSnapshots(launchSnapshotFilePath(a.launchSnapshotDir()), store.items)
	store.Unlock()
}

// ListLaunchSnapshots 返回最近快照（拷贝防外部篡改），按时间倒序。
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
