package main

import (
	"archive/zip"
	"strings"
)

type zipExtractLimits struct {
	EntryMax   int64 // 单个文件解压后的字节上限
	TotalMax   int64 // 本次解压全部文件合计字节上限
	MaxEntries int   // 条目总数上限（含目录），防海量空条目耗尽 inode
}
type zipPlannedEntry struct {
	file *zip.File
	rel  string // 已校验、统一使用 '/' 分隔的相对路径
	dir  bool
}

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
