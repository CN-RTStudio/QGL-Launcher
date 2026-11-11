package main

import (
	"archive/zip"
	"fmt"
	"os"
	"runtime"
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
func zipDuplicateKey(rel string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(rel)
	}
	return rel
}

func secureDestUnder(root, dest string) bool {
	return PathWithinRoot(dest, root)
}
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

	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("打开 zip 条目失败: %v", err)
	}
	defer rc.Close()

	n, err := secureStreamToFile(rc, destPath, privateFilePerm, entryMax)
	if err != nil {
		if n > entryMax {
			msg := fmt.Sprintf("zip 条目 %s 解压后超过单文件上限 %d(解压炸弹防护)", f.Name, entryMax)
			recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", msg)
			return 0, fmt.Errorf("%s", msg)
		}
		return 0, fmt.Errorf("解压条目 %s 失败: %v", f.Name, err)
	}
	return n, nil
}
