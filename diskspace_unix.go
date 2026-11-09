//go:build !windows

package main

// diskspace_unix.go —— Linux / macOS 下用 statfs(2) 探测某挂载点对普通用户
// 可用的字节数（Bavail 已扣除为 root 保留的块），再交给 diskspaceguard 的
// 纯函数裁决是否会击穿安全水位。

import (
	"path/filepath"
	"syscall"
)

// normalizeProbePath 把空路径收敛到当前目录，并做词法 Clean。
func normalizeProbePath(p string) string {
	if p == "" {
		return "."
	}
	return filepath.Clean(p)
}

// availableDiskBytes 返回 path 所在文件系统上“非特权用户可用”的字节数。
// 使用 Bavail（而非 Blocks/Bfree）：它已经扣除了为 root 保留的保留块，
// 与启动器这种普通用户进程真正能写入的量一致。
func availableDiskBytes(path string) (int64, error) {
	dir := normalizeProbePath(path)
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return diskAvailUnknown, err
	}
	avail := int64(st.Bsize) * int64(st.Bavail)
	if avail < 0 {
		// 某些 32 位平台字段是无符号且可能大于 MaxInt64，折叠成“未知”而非负数。
		return diskAvailUnknown, nil
	}
	return avail, nil
}

// probeDownloadDiskFit 探测 + 裁决的组合入口。探测失败结论为 unknown（不误杀）。
func probeDownloadDiskFit(path string, requested, inflight int64) DiskFitAssessment {
	avail, err := availableDiskBytes(path)
	if err != nil {
		return assessDiskFit(diskAvailUnknown, requested, inflight)
	}
	return assessDiskFit(avail, requested, inflight)
}
