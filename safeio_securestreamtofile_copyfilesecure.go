package main

import (
	"fmt"
	"os"
)

func copyFileSecure(srcPath, dstPath string, perm os.FileMode, maxBytes int64) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %w", err)
	}
	defer src.Close()
	if bad, err := isSymlinkOrSpecial(srcPath); err != nil {
		return err
	} else if bad {
		return fmt.Errorf("拒绝从符号链接或非普通文件复制: %s", srcPath)
	}
	if _, err := secureStreamToFile(src, dstPath, perm, maxBytes); err != nil {
		return err
	}
	return nil
}
