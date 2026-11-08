package main

// launchsnapshot_app.go —— 启动参数快照的 App 绑定与磁盘持久化。
//
// 与 sessionjournal_app.go 同构：内存态 + 磁盘文件。磁盘文件在 QGL 目录
// （0600 私有，原子写），读取有界；脏快照整体丢弃，不逐条修补。前端可通过
// Wails 暴露的 ListLaunchSnapshots 读取，不能在运行时被远程页面篡改。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// launchSnapshotFileName 固定文件名（“文件名稳定”便于测试断言）。
const launchSnapshotFileName = "launch-snapshot.json"

// launchSnapshotMaxReadBytes 读快照文件的上界（10 份 * 每份约 1KB 的余量）。
const launchSnapshotMaxReadBytes int64 = 256 * 1024

// defaultLaunchSnapshotStore 是包级单例（与 defaultSessionJournal 同风格）。
var defaultLaunchSnapshotStore launchSnapshotStore

// launchSnapshotStore 内存态：App 进程内权威真相（磁盘文件只是持久化副本）。
type launchSnapshotStore struct {
	sync.Mutex
	loaded bool
	items  []LaunchSnapshot
}

// launchSnapshotDir 返回快照目录（QGL 目录）。
func (a *App) launchSnapshotDir() string {
	return a.GetQGLDir()
}

// launchSnapshotFilePath 返回快照完整路径。
func launchSnapshotFilePath(qglDir string) string {
	return filepath.Join(qglDir, launchSnapshotFileName)
}

// loadLaunchSnapshots 有界读磁盘快照文件。文件缺失按空处理；脏结构整体丢弃。
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
