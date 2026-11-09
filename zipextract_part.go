package main

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
)

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

// zipResolveParentInside 在落盘前把"目标的父目录"解析到真实路径，再确认它仍在
// 解压根目录的真实路径之内。secureZipRelPath 只保证字面路径不穿越；若目标目录树
// 里预先存在 junction / 符号链接目录（例如上次解压留下的 overrides/dir 指向盘外），
// 字面路径合法也会写穿。这里用 filepath.EvalSymlinks 做一次真实归属复核。
