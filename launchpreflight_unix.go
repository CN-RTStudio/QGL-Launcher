//go:build !windows

package main

// launchpreflight_unix.go —— 非 Windows 平台的重解析点检测退化实现。
// Unix 符号链接已在 checkJavaBinary 里用 os.ModeSymlink 拒绝；此文件仅为
// 编译期提供同一接口（跨平台构建不报 undefined）。

func hasWindowsReparseAttribute(path string) bool {
	return false
}
