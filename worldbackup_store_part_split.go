package main

import (
	"archive/zip"
	"fmt"
	"os"
)

// restoreWorldBackup 把指定备份恢复成一个“全新、不覆盖”的世界目录。
//
// 恢复前强制重算 zip 的 UMFS 并与清单核对，防止备份被掉包 / 损坏后解出脏数据；
// 解压完全复用 zipextract 的 Zip Slip / 特殊条目 / 炸弹规划，空前缀表示 zip 内
// 路径就是相对世界根的完整相对路径。目标目录已存在时绝不覆盖，改为分配唯一名。
func restoreWorldBackup(savesDir, backupRoot, worldName, stamp string, lim WorldBackupLimits) (string, error) {
	lim = normalizeWorldBackupLimits(lim)
	if _, reason := validateWorldName(worldName); reason != nameRejectNone {
		return "", worldError("世界目录名不合法: " + reason)
	}
	dir, err := worldBackupDirFor(backupRoot, worldName)
	if err != nil {
		return "", err
	}
	meta, zipPath, err := readWorldBackupMeta(dir, worldName, stamp)
	if err != nil {
		return "", err
	}
	digest, err := umfsFileHex(zipPath)
	if err != nil {
		return "", fmt.Errorf("重算备份摘要失败: %w", err)
	}
	if meta.UMFS == "" || digest != meta.UMFS {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份 UMFS 摘要不一致，疑似损坏或被篡改: "+stamp)
		return "", worldError("备份完整性校验失败，已拒绝恢复")
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("打开备份 zip 失败: %w", err)
	}
	defer zr.Close()

	target, err := allocateRestoreDir(savesDir, worldName, stamp)
	if err != nil {
		return "", err
	}
	if err := ensurePrivateDir(target); err != nil {
		return "", err
	}
	zipLim := zipExtractLimits{
		EntryMax:   lim.MaxEntryBytes,
		TotalMax:   lim.MaxTotalBytes,
		MaxEntries: lim.MaxEntries,
	}
	// 空前缀：zip 内 "level.dat"、"region/r.0.0.mca" 等路径原样作为相对目标根路径。
	if _, _, err := extractZipPrefixes(zr.File, target, []string{""}, zipLim, nil); err != nil {
		os.RemoveAll(target)
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份恢复解压失败，已清理半成品: "+err.Error())
		return "", worldError("备份解压失败，已取消恢复")
	}
	if empty, _ := isWorldDirEmpty(target); empty {
		os.RemoveAll(target)
		return "", worldError("备份内容为空，已取消恢复")
	}
	return target, nil
}
