//go:build windows

package main

// diskspace_windows.go —— Windows 下用 GetDiskFreeSpaceEx 探测某目录所在卷的
// 调用方可用字节（freeAvailableBytes 已计入配额，而非裸 free space），再交给
// diskspaceguard 的纯函数裁决是否会击穿安全水位。

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// normalizeProbePath 把空路径收敛到当前目录，并做词法 Clean，
// 避免把空串 / 相对片段直接喂给宽字符转换。
func normalizeProbePath(p string) string {
	if p == "" {
		return "."
	}
	return filepath.Clean(p)
}

// availableDiskBytes 返回 path 所在卷上“当前用户可用”的字节数。
func availableDiskBytes(path string) (int64, error) {
	dir := normalizeProbePath(path)
	ptr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return diskAvailUnknown, err
	}
	var freeAvailable, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(ptr, &freeAvailable, &totalBytes, &totalFree); err != nil {
		return diskAvailUnknown, err
	}
	return int64(freeAvailable), nil
}

// probeDownloadDiskFit 探测 + 裁决的组合入口。探测失败时 assessDiskFit
// 会得到 diskAvailUnknown，结论为 unknown（不误杀合法下载）。
func probeDownloadDiskFit(path string, requested, inflight int64) DiskFitAssessment {
	avail, err := availableDiskBytes(path)
	if err != nil {
		return assessDiskFit(diskAvailUnknown, requested, inflight)
	}
	return assessDiskFit(avail, requested, inflight)
}
