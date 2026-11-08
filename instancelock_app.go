package main

// instancelock_app.go —— 实例并发启动锁的 App 绑定。
//
// 内存 map 是本进程内权威真相（单进程防重复启动同一实例），磁盘锁文件做跨进程
// 互斥（两个启动器进程抢同一实例时后者被拦）。启动前 acquire，游戏进程退出后
// 按 PID release（watchGameProcess 的 defer），进程被强杀时磁盘锁靠过期时长
// 兜底接管。

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// instanceLocks 保存“正在运行”的实例锁：VersionID -> 锁记录。
// 需在 App 上持有：minecraft.go 的 LaunchGame / watchGameProcess 会读写它。
var instanceLocks = struct {
	sync.Mutex
	items map[string]*InstanceLock
}{items: map[string]*InstanceLock{}}

// instanceLockDir 返回实例锁文件目录（QGL 目录，0600 私有）。
func (a *App) instanceLockDir() string {
	return a.GetQGLDir()
}

// acquireInstanceLock 尝试为指定版本实例上锁。
// 返回 (release func, err)：release 必须在游戏进程退出后调用一次；上锁失败返回
// 可读错误（前端据此提示“该实例已在运行”）。
func (a *App) acquireInstanceLock(versionID string) (func(), error) {
	if err := sanitizePathComponent(versionID); err != nil {
		return nil, fmt.Errorf("无效的版本ID: %v", err)
	}
	now := time.Now().UnixMilli()
	tokenBytes := make([]byte, 8)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("实例锁令牌生成失败: %v", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// 1) 内存 map 查重（同进程内重复启动）。
	instanceLocks.Lock()
	if _, ok := instanceLocks.items[versionID]; ok {
		instanceLocks.Unlock()
		return nil, fmt.Errorf("实例 %s 已在运行（本启动器已占用）", versionID)
	}
	instanceLocks.Unlock()

	// 2) 磁盘锁查重（跨进程互斥）。
	lockPath := filepath.Join(a.instanceLockDir(), instanceLockFileName(versionID))
	existing, err := loadInstanceLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("实例锁读取失败: %v", err)
	}
	verdict := decideInstanceLock(existing, now, instanceLockStaleAfter)
	if verdict.Kind == InstanceLockBlock {
		return nil, fmt.Errorf("实例 %s 已在运行：%s", versionID, verdict.Reason)
	}

	// 3) 写锁 + 登记内存 map。
	lock := makeInstanceLock(versionID, versionID, os.Getpid(), token, now)
	if err := saveInstanceLock(lockPath, lock); err != nil {
		return nil, fmt.Errorf("实例锁写入失败: %v", err)
	}
	instanceLocks.Lock()
	instanceLocks.items[versionID] = lock
	instanceLocks.Unlock()
	recordSecurityEvent(auditCategoryJarScan, auditSeverityInfo, auditActionDetected,
		"instance-lock", fmt.Sprintf("实例 %s 已上锁（PID %d）", versionID, os.Getpid()))
	return func() {
		a.releaseInstanceLock(versionID, token)
	}, nil
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
