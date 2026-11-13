package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

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

// isWorldDirEmpty 报告目录是否不含任何条目。解压后用它兜底发现“空备份”。
func isWorldDirEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil && err != io.EOF {
		return false, err
	}
	return len(names) == 0, nil
}

// allocateRestoreDir 在 saves 下为恢复结果分配一个不存在的目录：
// saves/<world>-restored-<stamp>，冲突时追加 -01..。绝不覆盖既有世界。
