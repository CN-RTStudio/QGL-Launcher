package main

import (
	"os"
	"path/filepath"
)

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

const maxCopyDirEntryBytes int64 = 256 << 20

func copyDirContents(srcDir string, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// ReadDir 不跟随链接：任何非常规文件（符号链接 / 设备 / 管道等）一律跳过。
		if entry.Type()&os.ModeType != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if size > maxCopyDirEntryBytes || total+size > maxNativeTotalBytes {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		// copyFileSecure 内部会再做一次源链接检查、目标链接拒绝，并以 LimitReader
		// 多读 1 字节发现“声明大小正常但读取中持续增长”的文件。
		if err := copyFileSecure(srcPath, dstPath, 0600, maxCopyDirEntryBytes); err != nil {
			continue
		}
		total += size
	}
	return nil
}
