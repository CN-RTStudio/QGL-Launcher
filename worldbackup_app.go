package main

import (
	"path/filepath"
	"strings"
)

func (a *App) worldBackupRoot() string {
	return filepath.Join(a.GetQGLDir(), worldBackupRootFolder)
}
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
