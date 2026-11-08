//go:build !windows

package main

// symlinkscan_unix.go —— Unix 平台符号链接检测：仅 Lstat 模式位即可。

import "os"

func platformSymlinkCheck(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		// 读取失败按“未知”处理：不误报为链接（扫描报告而非启动闸门），
		// 但也不影响其它条目的遍历。
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}
