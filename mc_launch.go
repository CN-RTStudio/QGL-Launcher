package main

import (
	"strings"
	"syscall"
	"time"
	"unsafe"

)

func findMinecraftWindow(targetPID int, processStartTime time.Time) (bool, bool) {
	found, isFML := false, false
	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		if found {
			return 0
		}
		className := make([]byte, 512)
		procGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&className[0])), 512)
		classNameStr := string(bytesToString(className))
		isMCWindow := classNameStr == "GLFW30" || classNameStr == "LWJGL" || classNameStr == "SunAwtFrame"
		if !isMCWindow {
			return 1
		}
		title := make([]byte, 512)
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 512)
		titleStr := string(bytesToString(title))
		if titleStr == "" || titleStr == "PopupMessageWindow" {
			return 1
		}
		if strings.HasPrefix(titleStr, "GLFW") && !strings.HasPrefix(titleStr, "FML") {
			return 1
		}
		var windowPID int
		procGetWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))
		if windowPID != targetPID {
			return 1
		}
		found = true
		isFML = strings.HasPrefix(titleStr, "FML")
		return 0
	})
	procEnumWindows.Call(cb, 0)
	return found, isFML
}

func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (a *App) GetDownloadProgress() DownloadProgress { return a.downloadProgress }
