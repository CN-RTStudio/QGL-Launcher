package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func sanitizeInstanceLock(raw *InstanceLock) bool {
	if raw == nil {
		return false
	}
	if raw.Version != instanceLockVersion {
		return false
	}
	if err := sanitizePathComponent(raw.VersionID); err != nil {
		return false
	}
	if raw.Dir == "" || len(raw.Dir) > 256 || strings.ContainsAny(raw.Dir, "/\\") {
		return false
	}
	if raw.PID <= 0 || raw.Token == "" || len(raw.Token) > 64 {
		return false
	}
	if raw.StartedAt <= 0 {
		return false
	}
	return true
}
func instanceLockFileName(versionID string) string {
	return "instance-" + versionID + ".lock"
}
func loadInstanceLock(path string) (*InstanceLock, error) {
	raw := &InstanceLock{}
	if err := readLocalJSONBounded(path, raw, 1<<20, "实例锁"); err != nil {
		if os.IsNotExist(err) || errors.Is(err, errLocalFileTooLarge) {
			return nil, nil
		}
		return nil, err
	}
	if !sanitizeInstanceLock(raw) {
		return nil, nil // 脏锁：按不存在处理，调用方走 allow/reclaim 决策
	}
	return raw, nil
}

// releaseInstanceLock 释放实例锁（token 校验 + 内存 map 移除 + 磁盘锁删除）。
func (a *App) releaseInstanceLock(versionID, token string) {
	instanceLocks.Lock()
	lock, ok := instanceLocks.items[versionID]
	if !ok || (token != "" && lock.Token != token) {
		instanceLocks.Unlock()
		return
	}
	delete(instanceLocks.items, versionID)
	instanceLocks.Unlock()

	lockPath := filepath.Join(a.instanceLockDir(), instanceLockFileName(versionID))
	_ = removeInstanceLock(lockPath, token)
	recordSecurityEvent(auditCategoryJarScan, auditSeverityInfo, auditActionDetected,
		"instance-lock", fmt.Sprintf("实例 %s 锁已释放", versionID))
}

// ListRunningInstances 返回当前正在运行的实例（前端“运行中”展示用）。
func (a *App) ListRunningInstances() []string {
	instanceLocks.Lock()
	defer instanceLocks.Unlock()
	ids := make([]string, 0, len(instanceLocks.items))
	for id := range instanceLocks.items {
		ids = append(ids, id)
	}
	return ids
}

// IsInstanceRunning 查询某实例是否正在运行（启动按钮置灰用）。
func (a *App) IsInstanceRunning(versionID string) bool {
	instanceLocks.Lock()
	defer instanceLocks.Unlock()
	_, ok := instanceLocks.items[versionID]
	return ok
}
