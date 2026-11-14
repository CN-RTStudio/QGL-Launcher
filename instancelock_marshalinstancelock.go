package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func marshalInstanceLock(lock *InstanceLock) ([]byte, error) {
	return json.Marshal(lock)
}

// makeInstanceLock 构造一条新锁记录（令牌调用方生成，保证唯一）。
func makeInstanceLock(versionID, dir string, pid int, token string, now int64) *InstanceLock {
	return &InstanceLock{
		Version:   instanceLockVersion,
		VersionID: versionID,
		Dir:       dir,
		PID:       pid,
		Token:     token,
		StartedAt: now,
	}
}

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

const (
	InstanceLockAllow   = "allow"
	InstanceLockBlock   = "block"
	InstanceLockReclaim = "reclaim"
)

// decideInstanceLock 纯函数决策：existing 为磁盘/内存里已存在的锁（可为 nil）。
func decideInstanceLock(existing *InstanceLock, now int64, staleAfter time.Duration) InstanceLockVerdict {
	if existing == nil {
		return InstanceLockVerdict{Kind: InstanceLockAllow, Reason: "无既有锁，允许启动"}
	}
	if existing.Version != instanceLockVersion {
		return InstanceLockVerdict{Kind: InstanceLockReclaim, Reason: "锁文件版本不兼容，视为残留"}
	}
	if existing.Token == "" {
		return InstanceLockVerdict{Kind: InstanceLockReclaim, Reason: "锁文件缺少令牌，视为残留"}
	}
	if existing.PID <= 0 {
		return InstanceLockVerdict{Kind: InstanceLockReclaim, Reason: "锁文件进程号非法，视为残留"}
	}
	age := now - existing.StartedAt
	if staleAfter > 0 && age > int64(staleAfter/time.Millisecond) {
		return InstanceLockVerdict{Kind: InstanceLockReclaim,
			Reason: "锁已过期（残留于异常退出），允许接管"}
	}
	return InstanceLockVerdict{Kind: InstanceLockBlock,
		Reason: "该实例已在运行（另一个启动器或本启动器先占用了锁）"}
}
