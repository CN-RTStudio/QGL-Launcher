package main

import (
	"archive/zip"
	"runtime"
	"strings"
)

// zipExtractLimits 是单次解压的统一上限。正常数据永远碰不到这些阈值，
// 只有明显炸磁盘 / 耗尽 inode 的异常压缩包才会触发。
type zipExtractLimits struct {
	EntryMax   int64 // 单个文件解压后的字节上限
	TotalMax   int64 // 本次解压全部文件合计字节上限
	MaxEntries int   // 条目总数上限（含目录），防海量空条目耗尽 inode
}

// zipPlannedEntry 是预检通过、等待落盘的一个条目。
type zipPlannedEntry struct {
	file *zip.File
	rel  string // 已校验、统一使用 '/' 分隔的相对路径
	dir  bool
}

// zipSegmentUnsafeReason 判定单个路径段在 Windows 上是否携带特殊语义，返回
// 空串表示安全。这些形态的共同点是"条目名与实际落盘结果不一致"：
//   - 冒号：NTFS 备用数据流（"a.jar:payload" 会写进 a.jar 的 ADS，主文件看似没变）；
//   - `<>"|?*`：Win32 非法字符，CreateFile 报错或被静默映射成别的名字；
//   - 控制字符 / 双向覆写 / 零宽字符：肉眼与日志里看不到，可做同名伪装；
//   - 尾随点或空格：Win32 落盘时被系统剥掉，"a.jar." 与 "a.jar" 会撞到同一个文件；
//   - 保留设备名：CON / NUL / COM1 之类会被当成设备而不是目录里的文件。
func zipSegmentUnsafeReason(seg string) string {
	if strings.ContainsRune(seg, ':') {
		return "alternate-data-stream"
	}
	if containsAnyByte(seg, "<>\"|?*") {
		return "illegal-character"
	}
	if containsControlByte(seg) || scanUnsafeRunes(seg) != nameRejectNone {
		return "invisible-character"
	}
	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		return "trailing-dot-or-space"
	}
	if isReservedDeviceName(stemOfName(seg)) {
		return "reserved-device-name"
	}
	return ""
}

// zipDuplicateKey 归一化"落盘后是否同一个文件"的比较键：Windows 文件系统大小写
// 不敏感，A.jar 与 a.jar 会互相覆盖；其它平台保持原样，避免误伤合法同名文件。
func zipDuplicateKey(rel string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(rel)
	}
	return rel
}
