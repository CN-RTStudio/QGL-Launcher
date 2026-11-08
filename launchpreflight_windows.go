//go:build windows

package main

// launchpreflight_windows.go —— Windows 平台的重解析点（reparse point）检测。
//
// 背景：Java 可执行文件路径来自用户配置。若该路径是一个 NTFS 符号链接 /
// junction（指向任意程序，例如被钓鱼拖进来的伪装 java.exe），cmd.Start 会
// 静默跟随链接执行目标程序。这里用 GetFileAttributes 直接读
// FILE_ATTRIBUTE_REPARSE_POINT 属性，命中即拒绝，从根上堵住“配置项被换成
// 链接入口”的执行路径。

import "golang.org/x/sys/windows"

// hasWindowsReparseAttribute 判断路径是否带重解析点属性。
// 任何读取/转换失败都按“未知”处理：返回 true 会在 preflight 中拒绝启动，
// 宁可误杀也不放行不可信执行目标。
func hasWindowsReparseAttribute(path string) bool {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return true
	}
	return attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
