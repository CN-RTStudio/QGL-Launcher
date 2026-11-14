package main

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	instanceLockStaleAfter = 15 * time.Minute // 锁文件超过该时长视为残留，可接管
	instanceLockVersion    = 1                // 锁文件格式版本
	instanceLockTokenLen   = 16               // 随机令牌长度（避免旧锁误释放新锁）
)

type InstanceLock struct {
	Version   int    `json:"version"`
	VersionID string `json:"versionId"` // 已净化的版本标识
	Dir       string `json:"dir"`       // 逻辑目录名（最后一段），不含绝对路径
	PID       int    `json:"pid"`
	Token     string `json:"token"`
	StartedAt int64  `json:"startedAt"` // Unix 毫秒
}
type InstanceLockVerdict struct {
	Kind   string `json:"kind"`   // allow / block / reclaim
	Reason string `json:"reason"` // 给人看的中文原因
}

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
