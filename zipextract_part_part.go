package main

import (
	"archive/zip"
	"fmt"
	"os"
)

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
