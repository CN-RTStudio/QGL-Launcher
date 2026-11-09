package main

// worldbackup_app.go —— 世界存档备份能力的 Wails 绑定薄封装。
// 纯备份 / 恢复内核在 worldbackup.go（不依赖 App 与平台 API，可独立单测）；
// 本文件只负责把受信的 .minecraft / QGL 目录解析出来，再转调内核。

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// worldBackupRoot 返回所有世界备份的隔离根：QGL/worldbackups。
func (a *App) worldBackupRoot() string {
	return filepath.Join(a.GetQGLDir(), worldBackupRootFolder)
}

// resolveSavesDir 解析本次操作的 saves 根。
//
// gameDirHint 为空表示跟随“非版本隔离”的默认布局（.minecraft/saves）；非空时只
// 允许指向 .minecraft 之内的实例目录（例如 versions/<id> 这种版本隔离布局）。
// 任何指向 .minecraft 之外的路径（绝对路径、盘符跳转、含 ".." 的逃逸）都拒绝。
func (a *App) resolveSavesDir(gameDirHint string) (string, error) {
	mcDir := a.GetMinecraftDir()
	if mcDir == "" {
		return "", worldError("无法解析 .minecraft 根目录")
	}
	gameDir := mcDir
	if hint := strings.TrimSpace(gameDirHint); hint != "" {
		candidate := filepath.Clean(hint)
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(mcDir, candidate)
		}
		if !PathWithinRoot(candidate, mcDir) {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
				"worldbackup", "世界备份 gameDir 越出 .minecraft 根: "+hint)
			return "", worldError("游戏目录必须位于 .minecraft 之内")
		}
		gameDir = candidate
	}
	savesDir := filepath.Join(gameDir, worldSavesFolder)
	if !PathWithinRoot(savesDir, mcDir) {
		return "", worldError("saves 目录解析越界")
	}
	return savesDir, nil
}

// ===== Wails 暴露给前端的方法（薄封装：解析受信根 -> 调内核）=====

// ListWorlds 列出当前布局 saves 目录下可备份的世界及其体量概要。
func (a *App) ListWorlds(gameDirHint string) ([]WorldInfo, error) {
	savesDir, err := a.resolveSavesDir(gameDirHint)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(savesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []WorldInfo{}, nil
		}
		return nil, worldError("读取 saves 目录失败")
	}
	lim := defaultWorldBackupLimits()
	worlds := make([]WorldInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if _, reason := validateWorldName(name); reason != nameRejectNone {
			continue
		}
		worldDir := filepath.Join(savesDir, name)
		// e.IsDir() 对符号链接（含指向目录的链接）返回 false，已在上面跳过，
		// 故到达此处的必然是真实目录；不要再用把普通目录当特殊项的判定，否则
		// 会把所有合法世界都过滤掉。
		planned, total, planErr := planWorldFiles(worldDir, lim)
		if planErr != nil {
			// 体量超限 / 含特殊链接的世界不可直接备份，但仍在列表里给出名字，
			// 体量留 0，让前端能看到并提示，而不是整列失败。
			worlds = append(worlds, WorldInfo{Name: name})
			continue
		}
		info := WorldInfo{Name: name, Entries: len(planned), TotalBytes: total}
		if fi, fErr := e.Info(); fErr == nil {
			info.ModTime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		worlds = append(worlds, info)
	}
	sort.Slice(worlds, func(i, j int) bool { return worlds[i].Name < worlds[j].Name })
	return worlds, nil
}

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
