package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func zipResolveParentInside(root, dest string) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("解析解压根目录真实路径失败: %v", err)
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("创建解压目录失败: %v", err)
	}
	parentReal, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("解析条目父目录真实路径失败: %v", err)
	}
	if !PathWithinRoot(parentReal, rootReal) {
		return fmt.Errorf("条目父目录真实路径越出解压根目录(junction/symlink 逃逸): %s", parentReal)
	}
	return nil
}

// extractPlannedZipEntries 按预检计划顺序落盘，并在真实复制时再次核对总量
// （元数据可能撒谎）。返回实际写入字节数与文件条目数。
