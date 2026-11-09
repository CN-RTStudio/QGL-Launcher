package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

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
