package main

import (
	"errors"
	"os"
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
