package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
func (a *App) RestoreWorldBackup(gameDirHint, worldName, stamp string) (string, error) {
	savesDir, err := a.resolveSavesDir(gameDirHint)
	if err != nil {
		return "", err
	}
	return restoreWorldBackup(savesDir, a.worldBackupRoot(),
		strings.TrimSpace(worldName), strings.TrimSpace(stamp), defaultWorldBackupLimits())
}

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

func pruneWorldBackups(dir string, keep int) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	stamps := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".zip") {
			continue
		}
		stamp := strings.TrimSuffix(name, ".zip")
		if validateWorldStamp(stamp) {
			stamps = append(stamps, stamp)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(stamps)))
	if len(stamps) <= keep {
		return 0, nil
	}
	removed := 0
	for _, stamp := range stamps[keep:] {
		if removed >= worldKeepMax {
			break
		}
		zipPath := filepath.Join(dir, stamp+".zip")
		metaPath := filepath.Join(dir, stamp+".json")
		if !PathWithinRoot(zipPath, dir) || !PathWithinRoot(metaPath, dir) {
			continue
		}
		if err := os.Remove(zipPath); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		_ = os.Remove(metaPath)
		removed++
	}
	return removed, nil
}
