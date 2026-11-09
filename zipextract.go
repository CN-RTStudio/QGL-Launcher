package main

// zipextract.go 把 zip / jar 解压落盘这条链上重复且各写各的安全逻辑收口到一处：
//
//  1. Zip Slip：条目名必须是受限相对路径，拒绝 ".."、绝对路径、盘符、反斜杠、NUL；
//     落盘前再做一次「目标绝对路径必须在根目录内」的复核。
//  2. 特殊条目：符号链接 / 设备 / 管道 / 套接字一律拒绝，绝不创建（防止链接写穿）。
//  3. 解压炸弹：先按 zip 元数据做条目数 / 单条声明体积 / 声明总量预检（一个字节都不落地
//     就能整体拒绝），落盘时仍用 LimitReader 多读 1 字节复核，不信任声明值。
//  4. 原子写：每个文件先写到同目录临时文件，完整通过体积校验后再 rename 就位，
//     目标位置若已存在符号链接则直接拒绝，避免沿预置链接写出根目录。
//
// 旧实现里 modpack.go、loader.go、minecraft.go 各有一套路径/体积判断，行为不一致
// （例如 maven 解压不拒符号链接、没有条目数和声明总量预检、直接 O_TRUNC 覆盖）。
// 本文件只提供公共内核，各调用点保留自己的前缀筛选与业务上限常量。

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

// secureZipRelPath 校验 zip 条目名（去掉业务前缀后的相对路径）是否安全。
//
// zip 规范规定条目名一律用 '/' 分隔；这里故意不做任何平台相关的 Clean，
// 而是逐段手工过一遍，保证 Windows / Linux 行为一致：
//   - 空名、NUL 字节、反斜杠、前导 '/'、Windows 盘符 / UNC 一律拒绝；
//   - 出现 ".." 段（任何位置）一律拒绝，"."、空段会被折叠；
//   - 折叠后为空（例如 "./" 本身）也拒绝。
func secureZipRelPath(name string) (string, bool) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", false
	}
	if strings.ContainsRune(name, '\\') {
		return "", false
	}
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	// Windows 盘符（C:x / C:/x）与传统 DOS 设备名前缀。
	if len(name) >= 2 && name[1] == ':' {
		return "", false
	}

	var segs []string
	for _, seg := range strings.Split(name, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", false
		default:
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		return "", false
	}
	for _, seg := range segs {
		if zipSegmentUnsafeReason(seg) != "" {
			return "", false
		}
	}
	return strings.Join(segs, "/"), true
}

// secureDestUnder 复核目标绝对路径必须位于 root 之内（或等于 root）。
// rel 已在 secureZipRelPath 里验过，这里是落盘前的第二道保险，
// 防止平台路径语义差异或上层拼接失误造成逃逸。归属判定统一走
// pathguard.go 的 PathWithinRoot（Clean + 卷名归一 + 边界前缀比较），
// 不再在这里各写一份 Abs/HasPrefix。
