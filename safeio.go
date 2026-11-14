package main

import (
	"fmt"
	"os"
)

const (
	// privateFilePerm 是敏感文件权限：仅属主可读写。
	privateFilePerm os.FileMode = 0o600
	// privateDirPerm 是敏感目录权限：仅属主可进入。
	privateDirPerm os.FileMode = 0o700
)

func isSymlinkOrSpecial(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}
	if info.IsDir() {
		return false, nil
	}
	// 命名管道、设备文件、socket 等也不是正常落盘目标。
	if !info.Mode().IsRegular() {
		return true, nil
	}
	return false, nil
}
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, privateDirPerm); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	if err := os.Chmod(dir, privateDirPerm); err != nil {
		return fmt.Errorf("收敛目录权限失败: %w", err)
	}
	return nil
}
