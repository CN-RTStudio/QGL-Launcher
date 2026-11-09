package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackupWorld 为指定世界创建一份安全备份，返回新备份的清单。
func (a *App) BackupWorld(gameDirHint, worldName string) (*WorldBackupMeta, error) {
	savesDir, err := a.resolveSavesDir(gameDirHint)
	if err != nil {
		return nil, err
	}
	worldDir, err := resolveWorldDir(savesDir, worldName)
	if err != nil {
		return nil, err
	}
	return createWorldBackup(worldDir, a.worldBackupRoot(), strings.TrimSpace(worldName),
		time.Now(), defaultWorldBackupLimits())
}

// ListWorldBackups 列出某世界的历史备份。
func (a *App) ListWorldBackups(worldName string) ([]WorldBackupMeta, error) {
	return listWorldBackups(a.worldBackupRoot(), strings.TrimSpace(worldName))
}

// RestoreWorldBackup 把指定备份恢复为新的世界目录，返回新目录绝对路径。
func (a *App) RestoreWorldBackup(gameDirHint, worldName, stamp string) (string, error) {
	savesDir, err := a.resolveSavesDir(gameDirHint)
	if err != nil {
		return "", err
	}
	return restoreWorldBackup(savesDir, a.worldBackupRoot(),
		strings.TrimSpace(worldName), strings.TrimSpace(stamp), defaultWorldBackupLimits())
}

// DeleteWorldBackup 删除某世界的一份备份（zip + 清单），仅允许删除受信备份根内
// 时间戳命名的文件。
func (a *App) DeleteWorldBackup(worldName, stamp string) error {
	cleanName, reason := validateWorldName(strings.TrimSpace(worldName))
	if reason != nameRejectNone {
		return worldError("世界目录名不合法: " + reason)
	}
	if !validateWorldStamp(strings.TrimSpace(stamp)) {
		return worldError("时间戳不合法")
	}
	dir, err := worldBackupDirFor(a.worldBackupRoot(), cleanName)
	if err != nil {
		return err
	}
	zipPath := filepath.Join(dir, stamp+".zip")
	metaPath := zipPathToManifestPath(zipPath)
	if !PathWithinRoot(zipPath, dir) || !PathWithinRoot(metaPath, dir) {
		return worldError("备份路径越界")
	}
	if err := os.Remove(zipPath); err != nil && !os.IsNotExist(err) {
		return worldError("删除备份失败")
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		return worldError("删除备份清单失败")
	}
	return nil
}
