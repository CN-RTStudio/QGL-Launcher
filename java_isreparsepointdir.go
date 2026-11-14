package main

import (
	"os"
	"syscall"
)

func isReparsePointDir(entry os.DirEntry) bool {
	info, err := entry.Info()
	if err != nil {
		return false
	}
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	return false
}

// searchDriveForJava 搜索磁盘驱动器上的 Java（参考PCL的磁盘遍历逻辑）
// 只搜索根目录下的 Java 相关文件夹，避免全盘递归太慢
