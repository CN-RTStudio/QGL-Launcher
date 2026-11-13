package main

import (
	"path/filepath"
	"strings"
)

type WorldInfo struct {
	Name       string `json:"name"`
	Entries    int    `json:"entries"`
	TotalBytes int64  `json:"totalBytes"`
	ModTime    string `json:"modTime"`
}

// WorldBackupMeta 是单个备份 zip 旁边的清单。UMFS 字段为备份内容的本地完整性摘要。
type WorldBackupMeta struct {
	WorldName  string `json:"worldName"`
	Stamp      string `json:"stamp"`
	CreatedAt  string `json:"createdAt"`
	Entries    int    `json:"entries"`
	TotalBytes int64  `json:"totalBytes"`
	ZipName    string `json:"zipName"`
	UMFS       string `json:"umfs"`
}

// worldPlannedFile 是预检通过、等待写入 zip 的一个普通文件。
type worldPlannedFile struct {
	abs  string
	rel  string // 统一 '/' 分隔、相对世界根的路径
	size int64
}

type worldError string

func (e worldError) Error() string { return string(e) }

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
