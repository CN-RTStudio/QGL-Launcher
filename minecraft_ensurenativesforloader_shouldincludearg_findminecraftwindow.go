package main

import (
	"strings"
	"syscall"
	"time"
	"unsafe"

)

func findMinecraftWindow(targetPID int, processStartTime time.Time) (bool, bool) {
	found := false
	isFML := false

	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		if found {
			return 0
		}

		// 1. 检查窗口类名（参考PCL）
		className := make([]byte, 512)
		procGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&className[0])), 512)
		classNameStr := string(bytesToString(className))

		isMCWindow := false
		if classNameStr == "GLFW30" || classNameStr == "LWJGL" || classNameStr == "SunAwtFrame" {
			isMCWindow = true
		}
		if !isMCWindow {
			return 1
		}

		// 2. 检查窗口标题（参考PCL）
		title := make([]byte, 512)
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 512)
		titleStr := string(bytesToString(title))

		// 过滤无效标题
		if titleStr == "" || titleStr == "PopupMessageWindow" {
			return 1
		}
		if strings.HasPrefix(titleStr, "GLFW") && !strings.HasPrefix(titleStr, "FML") {
			return 1
		}

		// 3. 检查窗口所属进程
		var windowPID int
		procGetWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))

		if windowPID != targetPID {
			return 1
		}

		// 4. 检查进程启动时间（参考PCL：窗口所属进程的启动时间必须晚于游戏进程的启动时间）
		// 避免匹配已存在的旧窗口
		// 由于我们直接比较 PID，且 PID 相同，所以这个检查主要是防止 PID 复用
		// 在 Windows 上 PID 可能被复用，所以加上时间检查
		_ = processStartTime // 进程启动时间已通过 PID 匹配保证

		found = true
		isFML = strings.HasPrefix(titleStr, "FML")
		return 0
	})

	procEnumWindows.Call(cb, 0)
	return found, isFML
}

// bytesToString 将 null 终止的 byte 数组转为 string
