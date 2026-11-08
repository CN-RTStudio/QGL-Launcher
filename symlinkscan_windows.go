//go:build windows

package main

// symlinkscan_windows.go —— Windows 平台的符号链接检测。
//
// Go 的 os.Lstat 会把 NTFS 符号链接与 junction 都标为 ModeSymlink，但
// 目录重解析点偶尔被当作普通目录读。因此这里双保险：先看 Lstat 模式，
// 再叠加 GetFileAttributes 的重解析点属性检测（复用 launchpreflight 的
// 同一个原语，口径一致）。

import "os"

func platformSymlinkCheck(path string) bool {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return hasWindowsReparseAttribute(path)
}
