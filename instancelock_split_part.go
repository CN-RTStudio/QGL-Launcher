package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

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
