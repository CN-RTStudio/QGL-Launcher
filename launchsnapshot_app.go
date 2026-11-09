package main

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
