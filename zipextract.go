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
	"fmt"
	"io"
	"os"
	"path/filepath"
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
func secureDestUnder(root, dest string) bool {
	return PathWithinRoot(dest, root)
}

// planZipEntries 对一批 zip 条目做只读预检，返回落盘计划。
//
// prefixes 是允许落地的条目名前缀（如 "maven/"、"overrides/"）；只有以这些
// 前缀开头的条目才会被接受，匹配后剥掉前缀再校验。重复落向同一相对路径的
// 条目直接判错（zip 允许重名，静默覆盖会让审计与实际结果不一致）。
func planZipEntries(files []*zip.File, prefixes []string, lim zipExtractLimits) ([]zipPlannedEntry, int64, error) {
	plan := make([]zipPlannedEntry, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	var declaredTotal int64

	for _, f := range files {
		var rel string
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name, prefix) {
				rel = f.Name[len(prefix):]
				break
			}
		}
		if rel == "" {
			continue
		}

		secureRel, ok := secureZipRelPath(rel)
		if !ok {
			err := fmt.Errorf("zip 条目路径不安全(Zip Slip 防护): %s", f.Name)
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
			return nil, 0, err
		}
		if f.Mode()&unsafeEntryMode != 0 {
			err := fmt.Errorf("zip 条目是不允许的特殊类型(符号链接/设备/管道/套接字): %s", f.Name)
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
			return nil, 0, err
		}
		if _, dup := seen[zipDuplicateKey(secureRel)]; dup {
			err := fmt.Errorf("zip 中存在重复落盘路径的条目: %s", f.Name)
			recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", err.Error())
			return nil, 0, err
		}
		seen[zipDuplicateKey(secureRel)] = struct{}{}

		isDir := f.FileInfo().IsDir() || strings.HasSuffix(secureRel, "/")
		if !isDir {
			if int64(f.UncompressedSize64) > lim.EntryMax {
				err := fmt.Errorf("zip 条目 %s 声明体积 %d 超过单文件上限 %d(解压炸弹防护)",
					f.Name, f.UncompressedSize64, lim.EntryMax)
				recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", err.Error())
				return nil, 0, err
			}
			declaredTotal += int64(f.UncompressedSize64)
			if declaredTotal > lim.TotalMax {
				err := fmt.Errorf("zip 条目声明总大小超过 %d 字节上限(解压炸弹防护)", lim.TotalMax)
				recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", err.Error())
				return nil, 0, err
			}
		}

		plan = append(plan, zipPlannedEntry{file: f, rel: secureRel, dir: isDir})
		if len(plan) > lim.MaxEntries {
			err := fmt.Errorf("zip 条目数超过 %d 上限(inode 耗尽防护)", lim.MaxEntries)
			recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", err.Error())
			return nil, 0, err
		}
	}
	return plan, declaredTotal, nil
}

// writeZipEntrySecure 以原子方式把一个文件条目写到 destPath。
//
// 流式 LimitReader 复制，多读 1 字节用于发现“声明很小、实际很大”的条目；
// 落盘期间使用同目录临时文件，成功后才 rename，任何失败都不留半成品。
func writeZipEntrySecure(f *zip.File, destPath string, entryMax int64) (int64, error) {
	if f.Mode()&unsafeEntryMode != 0 {
		err := fmt.Errorf("拒绝落地特殊类型 zip 条目: %s", f.Name)
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
		return 0, err
	}
	// 目标已存在且是符号链接时拒绝写入：攻击者可能预先布置链接，
	// 让普通文件写入沿链接穿透到根目录之外。
	if info, err := os.Lstat(destPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			err := fmt.Errorf("目标路径已存在符号链接，拒绝覆盖: %s", destPath)
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
			return 0, err
		}
	}

	parent := filepath.Dir(destPath)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return 0, fmt.Errorf("创建解压目录失败: %v", err)
	}

	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("打开 zip 条目失败: %v", err)
	}
	defer rc.Close()

	tmp, err := os.CreateTemp(parent, ".zipextract-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("创建临时文件失败: %v", err)
	}
	tmpName := tmp.Name()
	n, copyErr := io.Copy(tmp, io.LimitReader(rc, entryMax+1))
	closeErr := tmp.Close()
	if copyErr != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("解压条目 %s 失败: %v", f.Name, copyErr)
	}
	if closeErr != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("写入临时文件失败: %v", closeErr)
	}
	if n > entryMax {
		os.Remove(tmpName)
		err := fmt.Errorf("zip 条目 %s 解压后超过单文件上限 %d(解压炸弹防护)", f.Name, entryMax)
		recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", err.Error())
		return 0, err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("设置文件权限失败: %v", err)
	}
	if err := os.Rename(tmpName, destPath); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("替换目标文件失败: %v", err)
	}
	return n, nil
}

// zipResolveParentInside 在落盘前把"目标的父目录"解析到真实路径，再确认它仍在
// 解压根目录的真实路径之内。secureZipRelPath 只保证字面路径不穿越；若目标目录树
// 里预先存在 junction / 符号链接目录（例如上次解压留下的 overrides/dir 指向盘外），
// 字面路径合法也会写穿。这里用 filepath.EvalSymlinks 做一次真实归属复核。
func zipResolveParentInside(root, dest string) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("解析解压根目录真实路径失败: %v", err)
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("创建解压目录失败: %v", err)
	}
	parentReal, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("解析条目父目录真实路径失败: %v", err)
	}
	if !PathWithinRoot(parentReal, rootReal) {
		return fmt.Errorf("条目父目录真实路径越出解压根目录(junction/symlink 逃逸): %s", parentReal)
	}
	return nil
}

// extractPlannedZipEntries 按预检计划顺序落盘，并在真实复制时再次核对总量
// （元数据可能撒谎）。返回实际写入字节数与文件条目数。
func extractPlannedZipEntries(plan []zipPlannedEntry, destDir string, lim zipExtractLimits, logf func(string, ...any)) (int64, int, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return 0, 0, fmt.Errorf("创建解压根目录失败: %v", err)
	}

	var totalWritten int64
	fileCount := 0
	for _, pe := range plan {
		destPath := filepath.Join(destDir, filepath.FromSlash(pe.rel))
		if !secureDestUnder(destDir, destPath) {
			err := fmt.Errorf("zip 条目解析后越出目标目录(Zip Slip 防护): %s", pe.file.Name)
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
			return totalWritten, fileCount, err
		}
		if err := zipResolveParentInside(destDir, destPath); err != nil {
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
			return totalWritten, fileCount, err
		}
		if pe.dir {
			if err := os.MkdirAll(destPath, 0700); err != nil {
				return totalWritten, fileCount, fmt.Errorf("创建目录 %s 失败: %v", destPath, err)
			}
			continue
		}

		n, err := writeZipEntrySecure(pe.file, destPath, lim.EntryMax)
		if err != nil {
			return totalWritten, fileCount, err
		}
		totalWritten += n
		fileCount++
		if totalWritten > lim.TotalMax {
			err := fmt.Errorf("zip 实际解压总量超过 %d 字节上限(解压炸弹防护)", lim.TotalMax)
			recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", err.Error())
			return totalWritten, fileCount, err
		}
		logf("解压条目完成: %s (%d 字节)", pe.rel, n)
	}
	return totalWritten, fileCount, nil
}

// extractZipPrefixes 是调用方最常用的一站式入口：预检 + 落盘。
// prefixes 中靠前的前缀优先匹配。
func extractZipPrefixes(files []*zip.File, destDir string, prefixes []string, lim zipExtractLimits, logf func(string, ...any)) (int64, int, error) {
	plan, declared, err := planZipEntries(files, prefixes, lim)
	if err != nil {
		return 0, 0, err
	}
	if declared > lim.TotalMax {
		return 0, 0, fmt.Errorf("zip 声明总量 %d 超过上限 %d(解压炸弹防护)", declared, lim.TotalMax)
	}
	return extractPlannedZipEntries(plan, destDir, lim, logf)
}
