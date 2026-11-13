package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
func (a *App) ListWorldBackups(worldName string) ([]WorldBackupMeta, error) {
	return listWorldBackups(a.worldBackupRoot(), strings.TrimSpace(worldName))
}
