package main

// instancelock.go —— 游戏实例并发启动锁内核。
//
// 背景：
//   同一版本目录（versions/<versionID>）如果同时被两个启动器进程拉起两个 JVM，
//   两者会对同一个 .minecraft 实例目录并发读写（世界存档、配置、日志、崩溃报告），
//   轻则存档损坏、日志互相覆盖，重则两个进程互相争抢资源导致崩溃。历史上
//   LaunchGame 没有任何“同一实例只能启动一次”的保护——本模块补齐这道闸门。
//
// 设计要点：
//   - 决策纯函数化、可独立单测：给定“已存在的锁记录 + 当前时间 + 过期时长”，
//     返回 allow（无锁）/ block（锁仍新鲜，拒绝并发）/ reclaim（锁已过期，可
//     接管）。过期时长用于兜底“启动器进程被强杀后锁文件残留”的场景；
//   - 锁记录字段全部净化：VersionID 必须是合法路径段（复用 sanitizePathComponent
//     口径的字符级检查，不依赖文件系统）；Dir 只存“相对/逻辑标识”，不存绝对
//     路径，避免把本机目录结构写进日志与 UI；
//   - 锁写入走 0600 原子私有写（safeio 同款），读取有界、任何脏字段整体丢弃，
//     绝不半信任恢复；
//   - 同一 App 进程内用内存 map 作为“权威真相”，磁盘锁文件用于跨进程互斥，
//     二者合起来覆盖“双启动器进程同拉一个实例”与“单进程内重复启动同一实例”
//     两条路径。

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// sanitizeInstanceLock 逐字段净化锁记录；任何字段非法即整体拒绝。
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

// instanceLockFileName 生成锁文件名：随版本标识，避免不同实例互相干扰。
func instanceLockFileName(versionID string) string {
	return "instance-" + versionID + ".lock"
}

// loadInstanceLock 有界读取实例锁文件；不存在或损坏返回 nil（不报错，按无锁处理）。
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

// saveInstanceLock 原子私有写实例锁（0600）。
func saveInstanceLock(path string, lock *InstanceLock) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writePrivateJSONBounded(path, lock, 1<<20)
}

// removeInstanceLock 删除锁文件（token 不匹配时拒绝删除，防误删新锁）。
func removeInstanceLock(path, token string) error {
	existing, err := loadInstanceLock(path)
	if err != nil {
		return err
	}
	if existing != nil && existing.Token != token {
		return errors.New("实例锁令牌不匹配，拒绝删除")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// marshalInstanceLock 供调试 / 测试用：序列化锁记录。
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
