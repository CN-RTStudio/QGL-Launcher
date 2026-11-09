package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// createWorldBackup 是备份主流程：预检 -> 磁盘水位 -> 原子打包 -> UMFS 清单 ->
// 淘汰旧份。纯路径 / 文件操作，不依赖 App 字段，便于以临时目录单测。
func createWorldBackup(worldDir, backupRoot, worldName string, now time.Time, lim WorldBackupLimits) (*WorldBackupMeta, error) {
	lim = normalizeWorldBackupLimits(lim)
	planned, total, err := planWorldFiles(worldDir, lim)
	if err != nil {
		return nil, err
	}
	dir, err := worldBackupDirFor(backupRoot, worldName)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	// 落盘前做磁盘水位裁决：把源体积 + zip 临时膨胀余量一起申请，会击穿安全
	// 水位就直接拒绝，而不是先写满盘再失败。探测结论 unknown 时保守放行。
	requested := total + worldReserveHeadroom
	if requested < total {
		requested = total // 溢出保护
	}
	fit := probeDownloadDiskFit(dir, requested, 0)
	if fit.Verdict == diskFitShort {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionBlocked,
			"worldbackup", fmt.Sprintf("备份磁盘空间不足，缺口 %d 字节", fit.Shortfall))
		return nil, worldError("磁盘剩余空间不足，已取消备份")
	}

	stamp := now.UTC().Format(worldStampLayout)
	zipPath, err := uniqueStampZipPath(dir, stamp)
	if err != nil {
		return nil, err
	}
	entries, _, err := writeWorldZipAtomic(planned, zipPath, lim)
	if err != nil {
		return nil, err
	}
	digest, err := umfsFileHex(zipPath)
	if err != nil {
		os.Remove(zipPath)
		return nil, fmt.Errorf("计算备份摘要失败: %w", err)
	}
	meta := &WorldBackupMeta{
		WorldName:  worldName,
		Stamp:      stamp,
		CreatedAt:  now.UTC().Format(time.RFC3339),
		Entries:    entries,
		TotalBytes: total,
		ZipName:    filepath.Base(zipPath),
		UMFS:       digest,
	}
	if err := writePrivateJSONBounded(zipPathToManifestPath(zipPath), meta, 1<<20); err != nil {
		os.Remove(zipPath)
		return nil, fmt.Errorf("写入备份清单失败: %w", err)
	}
	_, _ = pruneWorldBackups(dir, lim.Keep)
	return meta, nil
}
