package main

import (
	"time"
)

// 实例锁的资源与语义常量。
const (
	instanceLockStaleAfter = 15 * time.Minute // 锁文件超过该时长视为残留，可接管
	instanceLockVersion    = 1                // 锁文件格式版本
	instanceLockTokenLen   = 16               // 随机令牌长度（避免旧锁误释放新锁）
)

// InstanceLock 是一条实例锁记录。
type InstanceLock struct {
	Version   int    `json:"version"`
	VersionID string `json:"versionId"` // 已净化的版本标识
	Dir       string `json:"dir"`       // 逻辑目录名（最后一段），不含绝对路径
	PID       int    `json:"pid"`
	Token     string `json:"token"`
	StartedAt int64  `json:"startedAt"` // Unix 毫秒
}

// InstanceLockVerdict 是实例锁决策的枚举结果。
type InstanceLockVerdict struct {
	Kind   string `json:"kind"`   // allow / block / reclaim
	Reason string `json:"reason"` // 给人看的中文原因
}

// 决策结果常量。
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
