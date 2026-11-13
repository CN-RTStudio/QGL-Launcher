package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
